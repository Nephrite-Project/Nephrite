==============================
How Nephrite differs from QEMU
==============================

Nephrite is QEMU's development tree as of commit f29ccc287a6 (version 11.1.50)
with the changes below. Each one is a commit of its own; ``git log --grep``
finds it by the words of its subject, which the entries quote where a
change is not plain from its description. The processor's documentation is
cited as Intel's Software Developer's Manual (SDM) 325462-093 and AMD's
Architecture Programmer's Manual (APM) 24593 rev. 3.45.


Names and packaging
===================

* The programs are ``nephrite-system-*``, ``nephrite-*`` (user mode),
  ``nephrite-img``, ``nephrite-io``, ``nephrite-nbd``,
  ``nephrite-storage-daemon``, ``nephrite-ga``, ``nephrite-edid``,
  ``nephrite-keymap``, ``nephrite-vnc``, ``nephrite-trace-stap``,
  ``nephrite-elf2dmp``, ``nephrite-pr-helper``, ``nephrite-vmsr-helper``,
  and, in libexec, ``nephrite-bridge-helper`` and
  ``nephrite-vhost-user-gpu``.
* Data, modules, configuration, and documentation live under directories
  named ``nephrite`` (``share/nephrite``, ``lib/nephrite``,
  ``/etc/nephrite``, ``share/doc/nephrite``); the man pages, translations
  (the ``nephrite`` gettext domain), icons, desktop entry, systemtap
  tapsets and probes (``nephrite.*``), and the plugin header
  (``include/nephrite/qemu-plugin.h``) are Nephrite's too, so that
  Nephrite and QEMU install side by side.
* The systemd units in ``contrib/systemd`` start Nephrite's programs, and
  those of the persistent reservation and RAPL MSR helpers are named
  after Nephrite, as are the helpers' default sockets and PID files and
  the directory where Nephrite looks for the modules of an upgraded
  installation (``/var/run/nephrite``), so that its helpers run next to
  QEMU's.
* Nephrite has version numbers of its own, starting at 0.1.0, in
  ``NEPHRITE_VERSION``; ``VERSION`` keeps the version of QEMU that
  Nephrite is based on. Its programs, and QMP's ``package`` member, show
  both ("Nephrite emulator version 0.1.0, based on QEMU 11.1.50"). QEMU's
  version stays alone where guests and management tools depend on it:
  QMP's ``qemu`` member, the machine types, the guest agent's
  ``guest-info``, and the version of the guest agent's Windows
  installer, which replaces QEMU's agent in place.
* Nephrite's release tags are ``v0.1.0`` and on. QEMU has tags of the
  same names for its old releases, so Nephrite's repository holds none
  of QEMU's tags; a clone that fetches QEMU's history must leave them
  out, with ``git fetch --no-tags`` or ``git config
  remote.<name>.tagOpt --no-tags``.
* Nephrite has its own logo, a green chip, in its icons, windows,
  documentation, and installers.
* Version and help texts, window titles and menus, the names that VNC,
  D-Bus, SPICE, and audio clients show, and the monitor's banner say
  Nephrite.
* QEMU's names stay where guests, drivers, management tools, or existing
  configurations depend on them: device and CPU model names and IDs, the
  fw_cfg signature, QMP and its ``qemu`` version member, the monitor's
  ``(qemu)`` prompt, SASL's ``qemu`` application name, ``QEMU_*``
  environment variables, and the guest agent's protocol, state directory,
  and Windows service and VSS provider.
* The documentation's text is QEMU's; its front page says so, and its
  examples run Nephrite's programs.
* QEMU's GitHub workflow that closed every pull request is gone. Pushing a
  version tag releases it on GitHub, with its source tarball.
* ``scripts/checkpatch.pl`` accepts trailers that credit AI tools, and
  ``AGENTS.md`` gives agents Nephrite's guidelines instead of QEMU's.


Firmware
========

The SeaBIOS images (``bios.bin``, ``bios-256k.bin``, ``bios-microvm.bin``,
and the ``vgabios-*.bin`` VGA BIOSes) are built, with QEMU's
configurations, from `ReBIOS's SeaBIOS
<https://github.com/ReBIOS-Project/seabios>`_, which is upstream SeaBIOS
with fixes, among them:

* Disk transfers that V86-mode code asks for go through a buffer that the
  V86 monitor maps one to one; AHCI used to take the caller's linear
  address as physical, so that Windows 9x installs on q35 corrupted their
  disks.
* Packet devices' unit attentions are read and the command retried, on
  AHCI and IDE; every read of a swapped CD used to fail.
* Misaligned ATAPI buffers are bounced on AHCI, and AHCI's link, error
  recovery, and transfer sizes are handled more robustly, as are NVMe's and
  SD cards'.
* A Phoenix-compatible A20 interface that HIMEM.SYS takes, which answers
  its queries correctly.

The images say ``-qemu-rebios`` in their version. What ReBIOS's SeaBIOS
adds for ReBIOS itself is built only into its CSM images, not into these.


New x86 features (TCG)
======================

Intel VMX, which QEMU's TCG does not have:

* VMX operation and VMCS access, VMX non-root operation with the full
  VM-entry checks, VM exits, and VMX aborts.
* EPT with 4-level and 5-level tables, accessed and dirty flags,
  mode-based execute control, and the advanced information on EPT
  violations; VPID.
* The TPR shadow, the APIC-access page, APIC-register virtualization,
  virtual-interrupt delivery, posted-interrupt processing, x2APIC
  virtualization, and IPI virtualization with the tertiary controls.
* The monitor trap flag, the preemption timer, and the HLT, shutdown, and
  wait-for-SIPI activity states.
* VMCS shadowing, TSC offsetting and scaling, PAUSE-loop exiting, RDRAND
  and RDSEED exiting, the XSAVES/XRSTORS control, VM functions with EPTP
  switching, page-modification logging, user wait and pause, the
  IA32_PERF_GLOBAL_CTRL and CET load controls, and exception injection
  with or without error codes.

AMD SVM, completing what QEMU's TCG has:

* Next-RIP saving, decode assists, VMCB clean bits, ASID-tagged
  translations with flushes by ASID, NMI virtualization, the PAUSE filter
  and its threshold, the TSC ratio MSR, VMSAVE/VMLOAD virtualization, LBR
  virtualization, ERAPS, GMET, read-only guest page tables (ROGPT),
  page-modification logging, TlbiCtl, the INVLPGB, TLBSYNC, idle HLT, and
  INVPCID intercepts, AVIC and x2AVIC, and CET state in the VMCB.

Processor features:

* PCID and INVPCID, INVLPGB and TLBSYNC, IA32_TSC_ADJUST and writable
  IA32_TSC, the local APIC's TSC-deadline mode, XSAVEC, XSAVES, XRSTORS,
  and IA32_XSS, LAM, LASS, WAITPKG (UMONITOR, UMWAIT, TPAUSE,
  IA32_UMWAIT_CONTROL), CPUID faulting, WRMSRNS, the speculation control
  MSRs, IA32_ARCH_CAPABILITIES, AMD's CPUID override MSRs, and AMD's
  breakpoint address masks.
* AMD's extended APIC space: the extended LVT entries, four or as many as
  the ``extapic-lvts`` CPU property asks for, up to eight (``max`` has
  eight), specific EOIs, and the interrupt enable registers, in xAPIC and
  x2APIC modes, which ``info lapic`` shows.
* The ``x2apic-locked`` CPU property emulates firmware that locked the
  local APIC in x2APIC mode, as recent Intel platforms do: the APIC comes
  out of reset in x2APIC mode and cannot leave it, as
  IA32_ARCH_CAPABILITIES[21], IA32_XAPIC_DISABLE_STATUS, and ``info
  lapic`` report (TCG and Intel CPU models only).
* A PMU: Intel's architectural performance monitoring (version 2) and
  AMD's core counters.
* CET: shadow stacks and indirect branch tracking.
* DebugCtl's branch recording (LBRs) and branch single-stepping.

Devices:

* A ``vga-pci`` property for a 64-bit framebuffer BAR.


Bug fixes
=========

Processor emulation (TCG):

* Segment limits and types are checked, as are the stack's room in far
  transfers and interrupts, far CALLs past their segment's limit, and
  interrupt handlers against their segment's limit; QEMU's TCG ignores
  segment limits.
* Task switches raise their exceptions in the new task, keep the old
  descriptors under the new selectors when loading them fails, check the
  stack limit of a task gate's error code, allow conforming code of a
  lower privilege level as the new task's CS, and faults while delivering
  external events set EXT.
* Far transfers set the accessed bit of the descriptors they load, and
  TR's cache stays busy, as LTR and task switches make it.
* MOV to CR0, CR3, CR4, and CR8 are checked as the processor checks them,
  system registers refuse non-canonical addresses, near branches to
  non-canonical addresses fault, and non-canonical or LASS-violating
  stack accesses raise #SS(0).
* PAE paging's PDPTE registers are loaded at MOV to CR and checked, and
  PDPTEs no longer get accessed flags.
* CR4.OSXSAVE is allowed wherever CPUID.01H:ECX.XSAVE is set, the XSAVE
  instructions raise #NM while CR0.TS is set, MXCSR is saved and loaded
  with the AVX state and refuses reserved bits, and unaligned accesses
  raise #AC with alignment checking.
* MSR accesses that the processor refuses fault; the Pentium's machine
  check MSRs read as 0.
* A #DB's DR6 bits are written as the exception is delivered, MOV SS's
  data breakpoints are held past the next instruction, instruction
  breakpoints match linear addresses, and AMD's address masks apply to
  instruction fetches.
* NMIs are held in the STI and MOV SS shadows, a second NMI waits behind a
  pending one, and the local APIC's timer keeps its count across mode
  changes.
* INIT ends HLT and MWAIT, except where VMX root operation blocks it or a
  clear GIF holds it (SDM Vol. 2A, HLT; APM 15.17, Table 15-10).
* TCG's processors can move their local APIC's registers to another base
  address.
* SMM entry and exit flush the TLB; changes to CR4.PKE and CR4.PKS flush
  it too.
* IGNNE# changes hflags2 only from the first CPU's thread ("Change
  hflags2 for IGNNE# only from the first CPU's thread").

AMD SVM (TCG):

* Injected interrupts are delivered once, not twice; virtual interrupts
  are taken only above V_TPR, and CR8 writes raise them without the BQL.
* EXITINTINFO reports interrupted NMIs and interrupts as such.
* INT3 and INTO check the exception intercepts, LMSW always takes the
  selective CR0 write intercept, CR read intercepts give their register's
  code, intercepts save the next RIP, RDTSCP has its own intercept, and
  MOV to CR's and MOV DR's operands are checked before the intercepts.
* A failing VMRUN leaves the guest's state in the VMCB alone.
* Nested page faults' error codes set the P bit for reserved-bit faults
  and I/D for fetches under the host's SMEP, and bit 8 of PML5Es and
  PML4Es is reserved on AMD processors.
* SVM guest mode has MMU indexes of its own.
* VMSAVE and VMLOAD virtualization is checked as the APM checks it.
* INIT is held while GIF is clear.

Devices:

* The Intel IOMMU posts interrupts: those through posted-format IRTEs go
  to their posted-interrupt descriptors, with notifications.
* The AMD IOMMU reads every DTE again at INVALIDATE_IOMMU_ALL.
* HPET FSB interrupts go through the IOMMU, with the DMAR and IVRS entries
  that let guests remap them.
* The AMD IOMMU names the southbridge by the root bus's ISA bridge, so
  that Linux enables interrupt remapping on q35.
* ATAPI completes the commands that a pending unit attention refuses; on
  AHCI they never completed, stalling each read of a swapped CD for 32
  seconds.

Memory and KVM:

* Device writes to RAM that a section maps read-only, as write-protected
  PAM segments map the shadowed BIOS and option ROMs, fail as writes to a
  ROM do, as the memory controller does not store them either (Intel 3
  Series Express Chipset Family Datasheet 316966-002, 5.1.18).
* Under KVM, such RAM is in read-only slots, so that the vCPUs' writes to
  write-protected PAM segments are dropped as on TCG.
* Once a store has made a page of RAM dirty, only the TLB entries that map
  that page stop checking stores for translated code, not other MMU
  indexes' entries for the same virtual address, which may map other RAM,
  as SVM guest mode's do; guests ran stale copies of code they had changed.


Behaviour changes
=================

* KVM's in-kernel PIT drops the ticks that a guest missed, as an 8254 and
  TCG's PIT do, where QEMU redelivers them back to back;
  ``-global kvm-pit.lost_tick_policy=delay`` brings QEMU's behaviour back.
* TCG's ``max`` CPU model has VMX; SVM tests need ``-cpu max,+svm,-vmx``.
* MWAIT without an armed monitor continues at once.
* The STI and MOV SS shadows hold external-interrupt and NMI VM exits.
* VMX MSR lists of more than 512 entries fail VM entry, as with Linux's
  KVM.
* ``EPYC-Genoa`` needs ``+sbpb,+ibpb-brtype`` for Linux's SRSO mitigation
  to come up without warnings, as under KVM.
* The PMU has no reference-cycles event.
* TCG's IA32_ARCH_CAPABILITIES has only the bits that hold for TCG,
  which is free of the issues they report; CPU models' other bits are
  dropped with a warning.


Known deviations and limits
===========================

* Segment limits: the 4 GiB wrap of flat segments is not checked; XSAVE
  checks the first 576 bytes of its area only; gathers and MPX bound tables
  are not checked; LOOP's ECX is already decremented when its target
  faults; a fetch past the limit on a page that is not present raises #PF;
  CMPS checks ES before DS; instructions that mix SS and other segments,
  and helpers' 64-bit stack accesses, raise #GP; VM switches drop a held
  MOV SS #DB.
* PDPTEs are read at walk time after task switches and RSM; under SVM's
  nested paging, guests see PDPEs read on demand, as on AMD processors.
* A processor still reaches its local APIC at FEE00000h after moving it.
* HPET FSB interrupts carry no requester ID, like the I/O APIC's.
* TCG's VMX: APIC-write emulation in an MMIO callback skips the rest of
  read-modify-write and REP instructions on trap-like exits; accesses to
  the APIC-access page during event delivery always exit, and
  guest-physical accesses to it are plain memory accesses; the rules on
  already-virtualized accesses are not tracked; unaligned MMIO accesses are
  split; PAUSE-loop exiting runs at TCG's speed; XSAVES at CPL > 0 keeps the
  #NM and #GP order; the NMI-unblocking bit (bit 12 of the exit
  qualification) is never set; MTF with BTF and TF reports BS as for
  non-branches.
* PMU: one cycle per instruction, no reference-cycles event, a simple
  branch-miss model, the edge bit ignored, no freeze on PMI, and no
  PerfMonV2, PEBS, or LBR format.
* CET: shadow-stack accesses without paging are allowed, EPT has no
  supervisor-shadow-stack control, nested page fault exit information
  lacks the shadow-stack bit, and ENDBR is recognized only as exactly
  ``F3 0F 1E FA`` and ``F3 0F 1E FB``.
* Not implemented: HOST_MCE_OVERRIDE, the bus-lock threshold, AMD's UAI,
  RDPRU, AMD's IBS, AMD-Vi's guest virtual APIC mode, and FRED.
* Unknown MSRs read as 0, as in QEMU.
* Writes through MemoryRegionCache (virtio's rings) still ignore
  read-only aliases.
* Under KVM, masking A20 has no effect, as in QEMU; port 92h and the
  keyboard controller do not OR their A20 gates as the chipset does, the
  last write wins.
* The Windows guest agent's installer registers QEMU's service and VSS
  provider names, so Nephrite's and QEMU's agents do not install side by
  side in one guest.
