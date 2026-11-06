/*
 * QEMU x86 CPU <-> APIC
 *
 * Copyright (c) 2003-2004 Fabrice Bellard
 *
 * SPDX-License-Identifier: MIT
 */

#include "qemu/osdep.h"
#include "qobject/qdict.h"
#include "qapi/error.h"
#include "monitor/monitor.h"
#include "monitor/hmp.h"
#include "system/hw_accel.h"
#include "system/kvm.h"
#include "system/tcg.h"
#include "system/xen.h"
#include "system/mshv.h"
#include "system/address-spaces.h"
#include "hw/core/qdev-properties.h"
#include "hw/i386/apic_internal.h"
#include "cpu-internal.h"

APICCommonClass *apic_get_class(Error **errp)
{
    const char *apic_type = "apic";

    /* TODO: in-kernel irqchip for hvf */
    if (kvm_enabled()) {
        if (!kvm_irqchip_in_kernel()) {
            error_setg(errp, "KVM does not support userspace APIC");
            return NULL;
        }
        apic_type = "kvm-apic";
    } else if (xen_enabled()) {
        apic_type = "xen-apic";
    } else if (whpx_irqchip_in_kernel()) {
        apic_type = "whpx-apic";
    } else if (mshv_enabled()) {
        apic_type = "mshv-apic";
    }

    return APIC_COMMON_CLASS(object_class_by_name(apic_type));
}

void x86_cpu_apic_create(X86CPU *cpu, Error **errp)
{
    APICCommonClass *apic_class = apic_get_class(errp);

    if (!apic_class) {
        return;
    }

    cpu->apic_state = APIC_COMMON(object_new_with_class(OBJECT_CLASS(apic_class)));
    object_property_add_child(OBJECT(cpu), "lapic",
                              OBJECT(cpu->apic_state));
    object_unref(OBJECT(cpu->apic_state));

    /* TODO: convert to link<> */
    cpu->apic_state->cpu = cpu;
    cpu->apic_state->apicbase = APIC_DEFAULT_ADDRESS | MSR_IA32_APICBASE_ENABLE;

    /* cpu must be set before realize, which validates the APIC ID */
    qdev_prop_set_uint32(DEVICE(cpu->apic_state), "id", cpu->apic_id);
}

/*
 * What a CPU reaches at the APIC's default base once it moved its APIC
 * away: no APIC, as apic_mem_read() has it for a disabled one, which the
 * SDM likens to a processor without one (Intel SDM 325462-093 Vol. 3A,
 * 13.4.3 and 13.12.2).
 */
static uint64_t apic_hole_read(void *opaque, hwaddr addr, unsigned size)
{
    return MAKE_64BIT_MASK(0, size * 8);
}

static void apic_hole_write(void *opaque, hwaddr addr, uint64_t val,
                            unsigned size)
{
}

static const MemoryRegionOps apic_hole_ops = {
    .read = apic_hole_read,
    .write = apic_hole_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
};

void x86_cpu_apic_realize(X86CPU *cpu, Error **errp)
{
    static bool apic_mmio_map_once;

    if (cpu->apic_state == NULL) {
        return;
    }
    qdev_realize(DEVICE(cpu->apic_state), NULL, errp);

    /* TCG: the registers for this CPU's accesses wherever it moves them. */
    if (tcg_enabled() && cpu->own_pages) {
        cpu->apic_moved_page = g_new(MemoryRegion, 1);
        memory_region_init_alias(cpu->apic_moved_page, OBJECT(cpu),
                                 "apic-moved", &cpu->apic_state->io_memory,
                                 0, 0x1000);
        memory_region_add_subregion(cpu->own_pages, X86_OWN_APIC,
                                    cpu->apic_moved_page);
        cpu->apic_hole_page = g_new(MemoryRegion, 1);
        memory_region_init_io(cpu->apic_hole_page, OBJECT(cpu),
                              &apic_hole_ops, cpu, "apic-hole", 0x1000);
        memory_region_add_subregion(cpu->own_pages, X86_OWN_APIC_HOLE,
                                    cpu->apic_hole_page);
    }

    /* Map APIC MMIO area */
    if (!apic_mmio_map_once) {
        memory_region_add_subregion_overlap(get_system_memory(),
                                            cpu->apic_state->apicbase &
                                            MSR_IA32_APICBASE_BASE,
                                            &cpu->apic_state->io_memory,
                                            0x1000);
        apic_mmio_map_once = true;
     }
}

#ifdef CONFIG_HMP
void hmp_info_local_apic(MonitorHMP *hmp, const QDict *qdict)
{
    CPUState *cs;

    if (qdict_haskey(qdict, "apic-id")) {
        int id = qdict_get_try_int(qdict, "apic-id", 0);

        cs = cpu_by_arch_id(id);
        if (cs) {
            cpu_synchronize_state(cs);
        }
    } else {
        cs = monitor_hmp_get_cpu(hmp);
    }


    if (!cs) {
        monitor_hmp_printf(hmp, "No CPU available\n");
        return;
    }
    x86_cpu_dump_local_apic_state(cs, CPU_DUMP_FPU);
}
#endif
