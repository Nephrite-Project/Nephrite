/*
 * bhyve (vmm.ko) in-kernel PIC (i8259) support
 *
 * Structure mirrors hw/i386/kvm/i8259.c: a container device owning the
 * primary/secondary chips, with IRQ lines forwarded to vmm's vatpic.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/isa/i8259_internal.h"
#include "hw/intc/i8259.h"
#include "qemu/module.h"
#include "system/bhyve.h"
#include "hw/core/irq.h"
#include "hw/core/qdev-properties.h"
#include "qapi/error.h"
#include "qom/object.h"
#include "bhyve-internal.h"

#define TYPE_BHYVE_I8259 "bhyve-i8259"
OBJECT_DECLARE_TYPE(BhyveI8259State, BhyveI8259Class, BHYVE_I8259)

struct BhyveI8259State {
    I8259CommonState parent_obj;
};

/**
 * BhyveI8259Class:
 * @parent_realize: The parent's realizefn.
 */
struct BhyveI8259Class {
    I8259CommonClass parent_class;

    DeviceRealize parent_realize;
};

#define TYPE_BHYVE_I8259_PIC "bhyve-i8259-pic"

struct BhyveI8259PICState {
    DeviceState parent_obj;

    ISABus *isabus;
    BhyveI8259State i8259[2];

    int irq_level[ISA_NUM_IRQS];
    uint64_t irq_count[ISA_NUM_IRQS];
};

OBJECT_DECLARE_SIMPLE_TYPE(BhyveI8259PICState, BHYVE_I8259_PIC)

/* vmm's vatpic state is not exported; nothing to sync. */
static void bhyve_i8259_get(I8259CommonState *cs)
{
}

static void bhyve_i8259_put(I8259CommonState *cs)
{
}

static bool bhyve_i8259_pic_get_statistics(InterruptStatsProvider *obj,
                                           uint64_t **irq_counts,
                                           unsigned int *nb_irqs)
{
    BhyveI8259PICState *s = BHYVE_I8259_PIC(obj);

    *irq_counts = s->irq_count;
    *nb_irqs = ARRAY_SIZE(s->irq_count);

    return true;
}

static void bhyve_i8259_reset(DeviceState *dev)
{
    I8259CommonState *cs = I8259_COMMON(dev);

    cs->elcr = 0;
    i8259_common_reset(cs);

    bhyve_i8259_put(cs);
}

static void bhyve_pic_set_irq(void *opaque, int irq, int level)
{
    BhyveI8259PICState *s = opaque;
    int err;

    i8259_stat_update_irq(s->irq_count, s->irq_level, irq, level);
    if (level) {
        err = vm_isa_assert_irq(bhyve_mach.vm, irq, -1);
    } else {
        err = vm_isa_deassert_irq(bhyve_mach.vm, irq, -1);
    }

    if (err) {
        fprintf(stderr, "bhyve: 8259 failed, irq (%d)\n", irq);
    }
}

static void bhyve_i8259_realize(DeviceState *dev, Error **errp)
{
    I8259CommonState *cs = I8259_COMMON(dev);
    BhyveI8259Class *bpc = BHYVE_I8259_GET_CLASS(dev);

    memory_region_init_io(&cs->base_io, OBJECT(dev), NULL, NULL,
                          "bhyve-pic", 2);
    memory_region_init_io(&cs->elcr_io, OBJECT(dev), NULL, NULL,
                          "bhyve-elcr", 1);

    bpc->parent_realize(dev, errp);
}

qemu_irq *bhyve_i8259_init(ISABus *bus)
{
    qemu_irq *irq_set;
    DeviceState *dev;
    int i;

    irq_set = g_new0(qemu_irq, ISA_NUM_IRQS);

    dev = qdev_new(TYPE_BHYVE_I8259_PIC);
    object_property_set_link(OBJECT(dev), "bus", OBJECT(bus), &error_fatal);
    qdev_realize_and_unref(dev, NULL, &error_fatal);

    for (i = 0; i < ISA_NUM_IRQS; i++) {
        irq_set[i] = qdev_get_gpio_in(dev, i);
    }

    return irq_set;
}

static void bhyve_i8259_class_init(ObjectClass *klass, const void *data)
{
    BhyveI8259Class *bpc = BHYVE_I8259_CLASS(klass);
    I8259CommonClass *k = I8259_COMMON_CLASS(klass);
    DeviceClass *dc = DEVICE_CLASS(klass);

    device_class_set_legacy_reset(dc, bhyve_i8259_reset);
    device_class_set_parent_realize(dc, bhyve_i8259_realize,
                                    &bpc->parent_realize);
    k->pre_save   = bhyve_i8259_get;
    k->post_load  = bhyve_i8259_put;
}

static void bhyve_i8259_pic_init(Object *obj)
{
    BhyveI8259PICState *s = BHYVE_I8259_PIC(obj);

    object_initialize_child(obj, "primary", &s->i8259[0], TYPE_BHYVE_I8259);
    object_initialize_child(obj, "secondary", &s->i8259[1], TYPE_BHYVE_I8259);

    qdev_init_gpio_in(DEVICE(obj), bhyve_pic_set_irq, ISA_NUM_IRQS);
}

static void bhyve_i8259_pic_realize(DeviceState *dev, Error **errp)
{
    BhyveI8259PICState *s = BHYVE_I8259_PIC(dev);
    DeviceState *pri_dev, *sec_dev;

    /* Primary */
    pri_dev = DEVICE(&s->i8259[0]);
    qdev_prop_set_uint32(pri_dev, "iobase", 0x20);
    qdev_prop_set_uint32(pri_dev, "elcr_addr", 0x4d0);
    qdev_prop_set_uint8(pri_dev, "elcr_mask", 0xf8);
    qdev_prop_set_bit(pri_dev, "master", 1);
    if (!isa_realize(ISA_DEVICE(pri_dev), s->isabus, errp)) {
        return;
    }

    /* Secondary */
    sec_dev = DEVICE(&s->i8259[1]);
    qdev_prop_set_uint32(sec_dev, "iobase", 0xa0);
    qdev_prop_set_uint32(sec_dev, "elcr_addr", 0x4d1);
    qdev_prop_set_uint8(sec_dev, "elcr_mask", 0xde);
    if (!isa_realize(ISA_DEVICE(sec_dev), s->isabus, errp)) {
        return;
    }
}

static const Property bhyve_i8259_pic_properties[] = {
    DEFINE_PROP_LINK("bus", BhyveI8259PICState, isabus, TYPE_ISA_BUS,
                     ISABus *),
};

static void bhyve_i8259_pic_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    InterruptStatsProviderClass *ic = INTERRUPT_STATS_PROVIDER_CLASS(klass);

    dc->realize = bhyve_i8259_pic_realize;
    device_class_set_props(dc, bhyve_i8259_pic_properties);
    ic->get_statistics = bhyve_i8259_pic_get_statistics;
    ic->print_info = i8259_pic_print_info;
    /* Reason: must be wired to the ISA bus via the "bus" property */
    dc->user_creatable = false;
}

static const TypeInfo bhyve_i8259_type_infos[] = {
    {
        .name = TYPE_BHYVE_I8259,
        .parent = TYPE_I8259_COMMON,
        .instance_size = sizeof(BhyveI8259State),
        .class_init = bhyve_i8259_class_init,
        .class_size = sizeof(BhyveI8259Class),
    },
    {
        .name = TYPE_BHYVE_I8259_PIC,
        .parent = TYPE_DEVICE,
        .class_init = bhyve_i8259_pic_class_init,
        .instance_init = bhyve_i8259_pic_init,
        .instance_size = sizeof(BhyveI8259PICState),
        .interfaces = (const InterfaceInfo[]) {
            { TYPE_INTERRUPT_STATS_PROVIDER },
            { }
        },
    },
};

DEFINE_TYPES(bhyve_i8259_type_infos)
