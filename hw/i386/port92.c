/*
 * QEMU I/O port 0x92 (System Control Port A, to handle Fast Gate A20)
 *
 * Copyright (c) 2003-2004 Fabrice Bellard
 *
 * SPDX-License-Identifier: MIT
 */

#include "qemu/osdep.h"
#include "system/runstate.h"
#include "migration/vmstate.h"
#include "hw/core/irq.h"
#include "hw/isa/isa.h"
#include "hw/i386/pc.h"
#include "trace.h"
#include "qom/object.h"

OBJECT_DECLARE_SIMPLE_TYPE(Port92State, PORT92)

struct Port92State {
    ISADevice parent_obj;

    MemoryRegion io;
    uint8_t outport;
    /* The keyboard controller's A20GATE output. */
    bool a20gate;
    qemu_irq a20_out;
};

/*
 * The A20 line: A20M# masks A20 only while both FAST_A20, port 92h's bit
 * 1, and the keyboard controller's A20GATE are 0 (Intel 82371AB PIIX4
 * datasheet 290562-001, 4.2.7.2; Intel 6 Series Chipset datasheet
 * 324645-006, 5.12.1.1).
 */
static void port92_update_a20(Port92State *s)
{
    qemu_set_irq(s->a20_out, (s->outport & 2) || s->a20gate);
}

static void port92_a20gate(void *opaque, int n, int level)
{
    Port92State *s = opaque;

    s->a20gate = level;
    port92_update_a20(s);
}

static void port92_write(void *opaque, hwaddr addr, uint64_t val,
                         unsigned size)
{
    Port92State *s = opaque;
    int oldval = s->outport;

    trace_port92_write(val);
    s->outport = val;
    port92_update_a20(s);
    if ((val & 1) && !(oldval & 1)) {
        qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
    }
}

static uint64_t port92_read(void *opaque, hwaddr addr,
                            unsigned size)
{
    Port92State *s = opaque;
    uint32_t ret;

    ret = s->outport;
    trace_port92_read(ret);

    return ret;
}

static bool port92_a20gate_needed(void *opaque)
{
    Port92State *s = opaque;

    return !s->a20gate;
}

static const VMStateDescription vmstate_port92_a20gate = {
    .name = "port92/a20gate",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = port92_a20gate_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_BOOL(a20gate, Port92State),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_port92_isa = {
    .name = "port92",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT8(outport, Port92State),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription * const []) {
        &vmstate_port92_a20gate,
        NULL
    }
};

/*
 * Port 92h is 00h after reset (Intel 82371AB PIIX4 datasheet 290562-001,
 * 4.2.7.2; Intel ICH10 datasheet 319973-003, 13.7.3): its A20 gate too;
 * the keyboard controller's output port comes out of reset with A20GATE
 * set.
 */
static void port92_reset(DeviceState *d)
{
    Port92State *s = PORT92(d);

    s->outport = 0;
    s->a20gate = true;
}

static const MemoryRegionOps port92_ops = {
    .read = port92_read,
    .write = port92_write,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 1,
    },
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void port92_initfn(Object *obj)
{
    Port92State *s = PORT92(obj);

    memory_region_init_io(&s->io, OBJECT(s), &port92_ops, s, "port92", 1);

    s->outport = 0;
    s->a20gate = true;

    qdev_init_gpio_in_named(DEVICE(obj), port92_a20gate, PORT92_A20GATE_LINE,
                            1);
    qdev_init_gpio_out_named(DEVICE(obj), &s->a20_out, PORT92_A20_LINE, 1);
}

static void port92_realizefn(DeviceState *dev, Error **errp)
{
    ISADevice *isadev = ISA_DEVICE(dev);
    Port92State *s = PORT92(dev);

    isa_register_ioport(isadev, &s->io, 0x92);
}

static void port92_class_initfn(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = port92_realizefn;
    device_class_set_legacy_reset(dc, port92_reset);
    dc->vmsd = &vmstate_port92_isa;
    /*
     * Reason: unlike ordinary ISA devices, this one needs additional
     * wiring: its A20 output line and the keyboard controller's A20GATE
     * input need to be wired up with qdev_connect_gpio_out_named().
     */
    dc->user_creatable = false;
}

static const TypeInfo port92_info = {
    .name          = TYPE_PORT92,
    .parent        = TYPE_ISA_DEVICE,
    .instance_size = sizeof(Port92State),
    .instance_init = port92_initfn,
    .class_init    = port92_class_initfn,
};

static void port92_register_types(void)
{
    type_register_static(&port92_info);
}

type_init(port92_register_types)
