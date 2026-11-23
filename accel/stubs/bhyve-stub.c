/*
 * FreeBSD vmm (bhyve) stubs for Nephrite: what code built once for every
 * accelerator uses where the accelerator is not built.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "system/bhyve.h"
#include "hw/intc/i8259.h"

bool bhyve_allowed;

bool bhyve_apic_in_platform(void)
{
    return false;
}

void *bhyve_ram_alloc(size_t size, uint64_t *alignment, int flags,
                      const char *name)
{
    g_assert_not_reached();
}

qemu_irq *bhyve_i8259_init(ISABus *bus)
{
    g_assert_not_reached();
}
