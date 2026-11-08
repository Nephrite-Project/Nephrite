==============================
How Nephrite differs from QEMU
==============================

Nephrite is QEMU's development tree as of commit f29ccc287a6 (version 11.1.50)
with the changes below. Each one is a commit of its own; ``git log --grep``
finds it by the words of its subject, which the entries quote where a
change is not plain from its description. The processor's documentation is
cited as Intel's Software Developer's Manual (SDM) 325462-093 and AMD's
Architecture Programmer's Manual (APM) 24593 rev. 3.46.


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
* ``scripts/qemu-binfmt-conf.sh`` registers Nephrite's user-mode programs
  as the interpreters of binfmt_misc's ``qemu-<cpu>`` entries, whose names
  stay QEMU's so that QEMU's and Nephrite's emulators do not both register
  for one architecture.
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
* The MP tables list the first logical CPU of each core rather than of
  each package; Windows NT 4.0 used to run on one processor of a
  multi-core package.

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
* User interrupts: the guest UINV field, the "load UINV" and "clear UINV"
  controls, injected and virtual user-interrupt notifications, and
  SENDUIPI with APIC virtualization.
* FRED: the FRED MSRs' guest and host fields with the "load FRED" VM-entry
  control and the secondary VM-exit controls "save FRED" and "load FRED",
  FRED event delivery of injected events with their event data, the
  nested-exception bit, and injected SYSCALL and SYSENTER, and the
  original-event data of VM exits during FRED event delivery.
* APX: the VM-exit extended instruction-information field, whose register
  numbers have five bits for R16 to R31, as the GPR fields of the exit
  qualifications of CR and DR accesses now have (Intel APX 355828-009,
  3.1.4.4.1).
* VMM bus-lock detection: a trap-like VM exit after any bus lock, also
  that of an implicit locked access, with the instruction's debug traps
  pending, and bit 26 of the exit reasons of VM exits during such an
  instruction.
* Register dumps show VMX operation: root or non-root, the VMXON region,
  and the current VMCS.

AMD SVM, completing what QEMU's TCG has:

* Next-RIP saving, decode assists, VMCB clean bits, ASID-tagged
  translations with flushes by ASID, NMI virtualization, the PAUSE filter
  and its threshold, the TSC ratio MSR, VMSAVE/VMLOAD virtualization, LBR
  virtualization, ERAPS, GMET, read-only guest page tables (ROGPT),
  page-modification logging, TlbiCtl, the INVLPGB, TLBSYNC, idle HLT, and
  INVPCID intercepts, AVIC and x2AVIC, CET state in the VMCB,
  HOST_MCE_OVERRIDE, and the bus lock threshold, whose count implicit
  locked accesses take too.
* VM_CR's LOCK and SVMDIS, and SVM-Lock's SVM_KEY MSR, with which STGI and
  SKINIT need no EFER.SVME.
* FRED virtualization (AMD64 FRED Virtualization 69191 rev. 1.10): VMRUN
  and #VMEXIT switch the FRED MSRs but IA32_FRED_RSP0, with their checks,
  and VMRUN checks FRED guests' rings; events injected into FRED guests
  take their event data, the nested-exception bit, and the INT1 and
  SYSCALL types; EXITINTINFO has its FRED form, with EXITINTDATA; and
  intercepted #DBs give their event data in EXITINFO2.
* Register dumps show VM_CR, host or guest mode, the host save area, the
  last VMCB, GIF, the nested page tables, G_PAT, and the bus lock threshold
  count.

Processor features:

* PCID and INVPCID, INVLPGB and TLBSYNC, IA32_TSC_ADJUST and writable
  IA32_TSC, the local APIC's TSC-deadline mode, whose deadline ``info
  lapic`` shows, XSAVEC, XSAVES, XRSTORS, and IA32_XSS, LAM, LASS, WAITPKG
  (UMONITOR, UMWAIT, TPAUSE, IA32_UMWAIT_CONTROL), CPUID faulting,
  WRMSRNS, LKGS, the speculation control MSRs, IA32_ARCH_CAPABILITIES,
  AMD's CPUID override MSRs, AMD's breakpoint address masks, AMD's fast
  FXSAVE and FXRSTOR, AMD's OS-visible workaround MSRs, AMD's topology
  extensions, AMD's misaligned SSE mode, AMD's upper address ignore, AMD's
  segment limit checks in 64-bit mode (EFER.LMSLE), CLZERO, IA32_MPERF and
  IA32_APERF with AMD's read-only copies of them, and RDPRU.
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
* CET: shadow stacks and indirect branch tracking, whose state register
  dumps show.
* User interrupts: their MSRs, delivery at CPL 3, user-interrupt
  notifications, UIRET with UIRET_UIF, CLUI, STUI, TESTUI, SENDUIPI, and
  the UINTR state component of XSAVES and XRSTORS; register dumps show
  their state.
* FRED: FRED event delivery with its stack levels, nested exceptions, and
  supervisor shadow-stack frames, ERETS and ERETU, the FRED MSRs, which
  register dumps show, SYSCALL and SYSENTER as FRED events, the far
  transfers and instructions that FRED transitions refuse, and NMI-source
  reporting, in FRED's event data and VMX's NMI exits.
* DebugCtl's branch recording (LBRs) and branch single-stepping, which
  register dumps show.
* OS bus-lock detection (DebugCtl.BLD): a trap-like #DB that clears
  DR6.BLD after an instruction at CPL > 0 whose locked access splits a
  cache line or has a memory type other than WB, which TLB entries keep
  as the PAT, EPT, nested paging, the MTRRs, and CR0.CD give it.
* Split-lock disable and UC-lock disable (MSR_MEMORY_CTRL, which
  IA32_CORE_CAPABILITIES[5] and CPUID.07H.02H:EDX[6] enumerate): #AC(0)
  and #AC(4) before such locked accesses, also the implicit ones that set
  accessed, dirty, and busy flags; register dumps show MSR_MEMORY_CTRL and
  DebugCtl.BLD.
* The EVEX forms of INVEPT, INVVPID, INVPCID, WRSS, and WRUSS, which
  QEMU's APX decoding lacks (Intel APX 355828-009, 3.1.5).

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
* PAE paging's PDPTE registers are loaded and checked at MOV to CR, at
  task switches that change CR3, and at RSM, and snapshots and migration
  keep them; guests under SVM's nested paging read the PDPEs on demand
  instead, as on AMD's processors. PDPTEs no longer get accessed flags.
* CR4.OSXSAVE is allowed wherever CPUID.01H:ECX.XSAVE is set, the XSAVE
  instructions raise #NM while CR0.TS is set, MXCSR is saved and loaded
  with the AVX state and refuses reserved bits, and unaligned accesses
  raise #AC with alignment checking.
* MSR accesses that the processor refuses fault, as do EFER writes that
  set reserved bits or change LME while paging is on, on AMD's processors
  those that change LMA, IA32_PAT writes of reserved memory types, and MTRR
  writes of reserved memory types, reserved bits, or addresses past
  MAXPHYADDR, as do accesses to the MTRRs where CPUID shows none; the
  Pentium's machine check MSRs read as 0.
* A #DB's DR6 bits are written as the exception is delivered, MOV SS's
  data breakpoints are held past the next instruction, whose instruction
  breakpoints Intel processors suppress, instruction breakpoints match
  linear addresses, and AMD's address masks apply to instruction fetches.
* NMIs are held in the STI and MOV SS shadows, a second NMI waits behind a
  pending one, on Intel's processors an IRET unblocks NMIs where it starts,
  even where it then faults, and the local APIC's timer keeps its count
  across mode changes.
* INIT ends HLT and MWAIT, except where VMX root operation blocks it or a
  clear GIF holds it (SDM Vol. 2A, HLT; APM 15.17, Table 15-10).
* The debugger's and the monitor's accesses to virtual memory (the
  gdbstub, ``x``, ``info tlb``, and ``info mem``) go through the nested
  paging of SVM guest mode and the EPT of VMX non-root operation, whose
  guests' page tables hold guest-physical addresses.
* TCG's processors can move their local APIC's registers to another base
  address, after which their accesses to the default base no longer reach
  them.
* SMM entry and exit flush the TLB; changes to CR4.PKE and CR4.PKS flush
  it too.
* SMI delivery and RSM load the debug registers as they are, without the
  checks and intercepts of MOV to DR, which had them raise #DB where
  DR7.GD was set, #GP, or SVM's DR-write #VMEXIT halfway through.
* The 64-bit SMM state-save area holds RFLAGS, DR6, DR7, and CR0 in
  quadwords and GDTR's and IDTR's limits in words, as AMD's table has
  them, so RSM no longer takes a reserved word for those limits' upper
  halves.
* RSM shuts the processor down where the state-save area holds state
  that the processor refuses there, with Intel's list on Intel's
  processors and AMD's on the others, before it restores anything.
* An SMI in SVM guest mode that the guest does not intercept runs the SMM
  handler outside the guest's controls, with the guest's VMCB, virtual
  interrupt state, and G_PAT and the host's control registers and EFER in
  the state-save area, and RSM returns to guest mode where the state-save
  area says so; the handler ran under the guest's intercepts and nested
  paging.
* SMIs save SSP in the state-save area, and RSM restores it made
  canonical.
* SMIs save and clear IA32_BNDCFGS, which RSM restores with its reserved
  bits clear and a canonical base.
* An SMI in the HLT state sets the state-save area's auto-halt restart
  field, for which RSM returns to the HLT state. MWAIT, which TCG takes as
  a halt on a single processor, no longer counts as the HLT state there or
  for user-interrupt notifications.
* SMIs put CR4.VMXE aside, which is reserved in SMM, and RSM restores it,
  shutting down where the state-save area sets it, and sets the CR0 and
  CR4 bits that VMX operation fixes, as the SDM's default treatment of SMIs
  and RSM has it.
* RSM takes EFER.LMA from EFER.LME, CR0.PG, and CR4.PAE, and on AMD's
  processors keeps EFER.SVME, takes CPL 0 in real mode and 3 in
  virtual-8086 mode, clears RFLAGS.VM outside protected mode and in long
  mode, and makes the bases of FS, GS, and the system tables canonical and
  those of the other segments 32-bit, as AMD's APM has it.
* IGNNE# changes hflags2 only from the first CPU's thread ("Change
  hflags2 for IGNNE# only from the first CPU's thread").
* CPUID leaf 0DH marks the CET and Arch LBR state components as
  supervisor ones, which IA32_XSS manages, for TCG as well as for KVM.
* CR4's upper half, which holds CR4.FRED, survives TCG's and the gdbstub's
  CR4 writes and SMM, whose state-save area has a quadword for CR4, and
  register dumps show it.

AMD SVM (TCG):

* Injected interrupts are delivered once, not twice; virtual interrupts
  are taken only above V_TPR, clear V_IRQ before their delivery, so that
  a #VMEXIT in it does not have them taken twice, and CR8 writes raise
  them without the BQL.
* EXITINTINFO reports interrupted NMIs and interrupts as such, INT3 and
  INTO as exceptions, and the exception delivered in place of an event
  whose delivery raised it.
* An exception in the delivery of an injected exception combines with it
  into a double fault or shutdown, as with a raised one, where QEMU
  delivered it as a first exception.
* A double fault that exceptions combine into checks the #DF intercept.
* INT3 and INTO check the exception intercepts, LMSW always takes the
  selective CR0 write intercept, CR read intercepts give their register's
  code, intercepts save the next RIP, RDTSCP has its own intercept, and
  MOV to CR's and MOV DR's operands are checked before the intercepts.
* SKINIT raises #GP outside CPL 0, before its intercept is checked.
* VMMCALL takes its intercept in guests whose EFER.SVME is clear, where
  QEMU raised #UD.
* A failing VMRUN leaves the guest's state in the VMCB alone.
* Under nested paging, the guest has a PAT of its own, G_PAT, which VMRUN
  checks and #VMEXIT saves; QEMU let the guest's PAT writes change the
  host's.
* Nested page faults' error codes set the P bit for reserved-bit faults
  and I/D for fetches under the host's SMEP, and bit 8 of PML5Es and
  PML4Es is reserved on AMD processors.
* SVM guest mode has MMU indexes of its own.
* VMSAVE and VMLOAD virtualization is checked as the APM checks it.
* INIT is held while GIF is clear.
* A guest's shutdown takes #VMEXIT only where the shutdown intercept is
  set; without it, the processor shuts down.
* Machine checks take the #MC intercept, and in guests with CR4.MCE clear
  the shutdown intercept, where QEMU delivered #MC to the guest or reset
  the machine.

Devices:

* The Intel IOMMU posts interrupts: those through posted-format IRTEs go
  to their posted-interrupt descriptors, with notifications.
* The AMD IOMMU has the guest virtual APIC mode: interrupts through
  GuestMode IRTEs go to vAPIC backing pages, with doorbells or GA log
  entries.
* The AMD IOMMU has one MSI capability. It had a second, unused one, which
  drivers that take the last MSI capability they find programmed instead.
* The AMD IOMMU reads every DTE again at INVALIDATE_IOMMU_ALL.
* HPET FSB interrupts go through the IOMMU, with the DMAR and IVRS entries
  that let guests remap them.
* The I/O APIC's and the HPETs' interrupts carry the requester IDs that the
  DMAR and IVRS give them, which VT-d checks against the source IDs of
  their interrupt remapping table entries.
* The AMD IOMMU names the southbridge by the root bus's ISA bridge, so
  that Linux enables interrupt remapping on q35.
* ATAPI completes the commands that a pending unit attention refuses; on
  AHCI they never completed, stalling each read of a swapped CD for 32
  seconds.
* The VGA and Cirrus VGA read the attribute controller's address register
  at 03C0 with the flip-flop either way. They read 0 with it in the data
  state, so Windows 3.1's standard mode, which saves the register on
  switching away from a DOS session, blanked the screen on switching back.
* Port 92h is 00h after a reset, its A20 gate included, which it kept.

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
* TCG's ``max`` CPU model has VMX, user interrupts, and FRED; SVM tests,
  written for AMD processors without them, need
  ``-cpu max,+svm,-vmx,-uintr,-fred``.
* MWAIT without an armed monitor continues at once.
* The STI and MOV SS shadows hold external-interrupt and NMI VM exits.
* VMX MSR lists of more than 512 entries fail VM entry, as with Linux's
  KVM.
* ``EPYC-Milan``, ``EPYC-Genoa``, and ``EPYC-Turin`` report that EFER.LMSLE
  is reserved (CPUID 8000_0008H:EBX[20], ``efer-lmsle-mbz``), as those
  processors do.
* Under TCG, the named CPU models also have the features of their
  processors that KVM does not give its guests, as the SDM's MSR tables,
  AMD's BKDGs and PPRs, and InstLatx64's CPUID dumps show them: IA32_MPERF
  and IA32_APERF (``aperfmperf``) on the Intel models from ``coreduo`` and
  ``n270`` on, on ``Opteron_G4`` and the later AMD models, on ``Dhyana``,
  and on ``YongFeng``; AMD's read-only copies of them (``eff-freq-ro``) on
  ``Opteron_G5``, the EPYC models, and ``Dhyana``; RDPRU (``rdpru``) from
  ``EPYC-Rome`` on; and UAI (``uai``) on ``EPYC-Genoa`` and
  ``EPYC-Turin``. ``ClearwaterForest`` and ``DiamondRapids`` go without
  them, as no MSR table or CPUID dump covers those processors yet.
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
  MOV SS #DB; CLZERO checks the segment at the byte that rAX gives, not
  over its cache line.
* PDPTE registers: RSM reloads them wherever it returns to PAE paging and
  shuts the processor down where they set reserved bits, which AMD's APM
  gives only for EFER.SVME set and without what invalid ones do, and Intel's
  SDM does not say; a task switch to a CR3 whose PDPTEs set reserved bits
  raises #GP in the old task with nothing switched, one of the outcomes
  that the SDM allows.
* The 64-bit SMM state-save area keeps AMD's layout on Intel's processors
  too, as QEMU's and KVM's do, which puts Intel's fields elsewhere: SSP and
  the auto-halt restart field at AMD's places for them, FF18h and FEC9h
  (Intel's 7EC8H and 7F02H), and the record of EPT at SMIs in VMX non-root
  operation at FF04h and FF08h and IA32_BNDCFGS at FF10h (Intel's 7EE0H,
  7ED8H, and 7ED0H, where AMD's layout has SVM's fields and EFER).
* RSM on Intel's processors restores CPL, RFLAGS.VM, and the segment bases
  as the state-save area has them, which the SDM does not cover. RSM back
  to SVM guest mode restores the controls that the SMI set aside, not
  those that the VMCB holds by then, which the APM does not cover either.
* TCG's VMX: APIC-write emulation in an MMIO callback skips the rest of
  read-modify-write and REP instructions on trap-like exits; accesses to
  the APIC-access page during event delivery always exit, and
  guest-physical accesses to it are plain memory accesses; the rules on
  already-virtualized accesses are not tracked; unaligned MMIO accesses are
  split; PAUSE-loop exiting runs at TCG's speed; XSAVES at CPL > 0 keeps the
  #NM and #GP order; MTF with BTF and TF reports BS as for non-branches.
* SVM's PAUSE filter threshold counts cycles as the PMU does.
* PMU: one cycle per instruction, no reference-cycles event, a simple
  branch-miss model, the edge bit ignored, no freeze on PMI, and no
  PerfMonV2, PEBS, or LBR format.
* CET: shadow-stack accesses without paging are allowed, EPT has no
  supervisor-shadow-stack control, nested page fault exit information
  lacks the shadow-stack bit, and ENDBR is recognized only as exactly
  ``F3 0F 1E FA`` and ``F3 0F 1E FB``.
* FRED: SYSCALL under FRED does not need IA32_EFER.SCE, as the SDM's
  operation of SYSCALL has it. SVM keeps the FRED MSRs at the state-save
  area offsets of the APM's Table B-2, where the KVM patches AMD posted
  ("KVM: SVM: Enable FRED support" v2, April 2026) have them 400h lower,
  and leaves IA32_PL0_SSP, for which the VMCB has no field, to the
  hypervisor.
* Not implemented: AMD's IBS, and SKINIT, which raises #UD where it does
  not exit. VM_CR's DPD, R_INIT, and DIS_A20M hold what software writes but
  do nothing.
* Bus locks: OS bus-lock detection skips the implicit supervisor accesses
  of descriptor and paging-structure updates, as AMD's APM says and
  Intel's SDM does not; with CR0.CD set every locked access is a bus lock,
  as AMD's CD memory type has it; VM entries take BLD in the pending
  debug exceptions, which the SDM's Table 27-4 defines and its 29.3.1.5
  still lists as reserved; and the flag updates in EPT's and nested
  paging's own tables are no bus locks.
* MPERF and APERF both count the TSC's ticks outside HLT, MWAIT, and the
  wait for SIPI, as the processor always runs at its nominal frequency.
  RDPRU sets CF where ECX names a register and clears it otherwise; the APM
  says that RDPRU modifies CF, not how.
* Unknown MSRs read as 0, as in QEMU.
* Writes through MemoryRegionCache (virtio's rings) still ignore
  read-only aliases.
* Under KVM, masking A20 has no effect, as in QEMU; port 92h and the
  keyboard controller do not OR their A20 gates as the chipset does, the
  last write wins.
* The Windows guest agent's installer registers QEMU's service and VSS
  provider names, so Nephrite's and QEMU's agents do not install side by
  side in one guest.
