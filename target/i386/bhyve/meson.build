# SPDX-License-Identifier: GPL-2.0-or-later

i386_system_ss.add(when: 'CONFIG_BHYVE', if_true:
  files(
  'bhyve-all.c',
  'bhyve-i8259.c',
  'bhyve-apic.c',
  'bhyve-ioapic.c',
  'bhyve-accel-ops.c',
  )
)

i386_system_ss.add(when: 'CONFIG_BHYVE', if_true: bhyve)

