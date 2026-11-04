/*
 * x86 VMX helpers (system emulator)
 *
 * The VMX instructions, the VMCS, and the VMX capability MSRs, as Intel's
 * Software Developer's Manual 325462-093, Volume 3C, Chapters 25 to 33 and
 * Volume 3D, Appendices A and B, describe them.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/host-utils.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cputlb.h"
#include "accel/tcg/cpu-ldst.h"
#include "accel/tcg/cpu-loop.h"
#include "system/runstate.h"
#include "system/memory.h"
#include "exec/page-protection.h"
#include "hw/i386/apic.h"
#include "tcg/helper-tcg.h"

/* The VMCS revision identifier IA32_VMX_BASIC reports. */
#define VMX_VMCS_REVISION 0x51454d55

/*
 * TCG's layout of a VMCS region: the revision identifier and the VMX-abort
 * indicator where the SDM puts them, then the launch state and the fields,
 * 8 bytes each, in the order of vmcs_fields[].
 */
#define VMCS_LAUNCH_OFFSET 8
#define VMCS_FIELDS_OFFSET 16

/* VMCS field encodings (Intel SDM 325462-093 Vol. 3C, 27.11.2). */
#define VMCS_ENC_HIGH 1
#define VMCS_ENC_INDEX(e) (((e) >> 1) & 0x1ff)
#define VMCS_ENC_TYPE(e) (((e) >> 10) & 3)
#define VMCS_ENC_WIDTH(e) (((e) >> 13) & 3)
#define VMCS_TYPE_EXIT_INFO 1
#define VMCS_WIDTH_16 0
#define VMCS_WIDTH_64 1
#define VMCS_WIDTH_32 2

/* VM-instruction error numbers (Intel SDM 325462-093 Vol. 3C, 33.4). */
#define VMXERR_VMCALL_ROOT 1
#define VMXERR_VMCLEAR_ADDR 2
#define VMXERR_VMCLEAR_VMXON 3
#define VMXERR_VMLAUNCH_NONCLEAR 4
#define VMXERR_VMRESUME_NONLAUNCHED 5
#define VMXERR_ENTRY_CONTROLS 7
#define VMXERR_ENTRY_HOST_STATE 8
#define VMXERR_VMPTRLD_ADDR 9
#define VMXERR_VMPTRLD_VMXON 10
#define VMXERR_VMPTRLD_REVISION 11
#define VMXERR_FIELD 12
#define VMXERR_READ_ONLY 13
#define VMXERR_VMXON_ROOT 15
#define VMXERR_ENTRY_MOV_SS 26
#define VMXERR_INV_OPERAND 28

/*
 * The VMCS fields VM entries and exits use (Intel SDM 325462-093 Vol. 3D,
 * Appendix B).
 */
#define VMCS_VPID 0x0000
#define VMCS_PI_NOTIFICATION_VECTOR 0x0002
#define VMCS_LAST_PID_INDEX 0x0008
#define VMCS_GUEST_SEL(seg) (0x0800 + 2 * (seg))
#define VMCS_GUEST_INTR_STATUS 0x0810
#define VMCS_PML_INDEX 0x0812
#define VMCS_HOST_SEL(seg) (0x0c00 + 2 * (seg))
#define VMCS_HOST_TR_SEL 0x0c0c
#define VMCS_IO_BITMAP_A 0x2000
#define VMCS_IO_BITMAP_B 0x2002
#define VMCS_MSR_BITMAP 0x2004
#define VMCS_EXIT_MSR_STORE_ADDR 0x2006
#define VMCS_EXIT_MSR_LOAD_ADDR 0x2008
#define VMCS_ENTRY_MSR_LOAD_ADDR 0x200a
#define VMCS_PML_ADDR 0x200e
#define VMCS_TSC_OFFSET 0x2010
#define VMCS_VIRTUAL_APIC_ADDR 0x2012
#define VMCS_APIC_ACCESS_ADDR 0x2014
#define VMCS_PI_DESC_ADDR 0x2016
#define VMCS_VMFUNC_CONTROLS 0x2018
#define VMCS_EOI_EXIT_BITMAP(n) (0x201c + 2 * (n))
#define VMCS_EPTP_LIST_ADDR 0x2024
#define VMCS_VMREAD_BITMAP 0x2026
#define VMCS_VMWRITE_BITMAP 0x2028
#define VMCS_XSS_EXIT_BITMAP 0x202c
#define VMCS_TSC_MULTIPLIER 0x2032
#define VMCS_PROC3_CONTROLS 0x2034
#define VMCS_PID_TABLE_ADDR 0x2042
#define VMCS_GUEST_PHYS_ADDR 0x2400
#define VMCS_LINK_POINTER 0x2800
#define VMCS_GUEST_DEBUGCTL 0x2802
#define VMCS_GUEST_PAT 0x2804
#define VMCS_GUEST_EFER 0x2806
#define VMCS_GUEST_PERF_GLOBAL_CTRL 0x2808
#define VMCS_GUEST_PDPTE(n) (0x280a + 2 * (n))
#define VMCS_HOST_PAT 0x2c00
#define VMCS_HOST_EFER 0x2c02
#define VMCS_HOST_PERF_GLOBAL_CTRL 0x2c04
#define VMCS_PIN_CONTROLS 0x4000
#define VMCS_PROC_CONTROLS 0x4002
#define VMCS_EXCEPTION_BITMAP 0x4004
#define VMCS_PF_ERROR_MASK 0x4006
#define VMCS_PF_ERROR_MATCH 0x4008
#define VMCS_CR3_TARGET_COUNT 0x400a
#define VMCS_EXIT_CONTROLS 0x400c
#define VMCS_EXIT_MSR_STORE_COUNT 0x400e
#define VMCS_EXIT_MSR_LOAD_COUNT 0x4010
#define VMCS_ENTRY_CONTROLS 0x4012
#define VMCS_ENTRY_MSR_LOAD_COUNT 0x4014
#define VMCS_ENTRY_INTR_INFO 0x4016
#define VMCS_ENTRY_EXCEPTION_ERROR 0x4018
#define VMCS_ENTRY_INSN_LEN 0x401a
#define VMCS_TPR_THRESHOLD 0x401c
#define VMCS_PLE_GAP 0x4020
#define VMCS_PLE_WINDOW 0x4022
#define VMCS_PROC2_CONTROLS 0x401e
#define VMCS_EXIT_REASON 0x4402
#define VMCS_EXIT_INTR_INFO 0x4404
#define VMCS_EXIT_INTR_ERROR 0x4406
#define VMCS_IDT_VECTORING_INFO 0x4408
#define VMCS_IDT_VECTORING_ERROR 0x440a
#define VMCS_EXIT_INSN_LEN 0x440c
#define VMCS_EXIT_INSN_INFO 0x440e
#define VMCS_GUEST_LIMIT(seg) (0x4800 + 2 * (seg))
#define VMCS_GUEST_GDTR_LIMIT 0x4810
#define VMCS_GUEST_IDTR_LIMIT 0x4812
#define VMCS_GUEST_AR(seg) (0x4814 + 2 * (seg))
#define VMCS_GUEST_INTERRUPTIBILITY 0x4824
#define VMCS_GUEST_ACTIVITY 0x4826
#define VMCS_GUEST_SYSENTER_CS 0x482a
#define VMCS_PREEMPTION_TIMER 0x482e
#define VMCS_HOST_SYSENTER_CS 0x4c00
#define VMCS_CR0_MASK 0x6000
#define VMCS_CR4_MASK 0x6002
#define VMCS_CR0_SHADOW 0x6004
#define VMCS_CR4_SHADOW 0x6006
#define VMCS_CR3_TARGET(n) (0x6008 + 2 * (n))
#define VMCS_EXIT_QUALIFICATION 0x6400
#define VMCS_GUEST_LINEAR_ADDR 0x640a
#define VMCS_GUEST_CR0 0x6800
#define VMCS_GUEST_CR3 0x6802
#define VMCS_GUEST_CR4 0x6804
#define VMCS_GUEST_BASE(seg) (0x6806 + 2 * (seg))
#define VMCS_GUEST_GDTR_BASE 0x6816
#define VMCS_GUEST_IDTR_BASE 0x6818
#define VMCS_GUEST_DR7 0x681a
#define VMCS_GUEST_RSP 0x681c
#define VMCS_GUEST_RIP 0x681e
#define VMCS_GUEST_RFLAGS 0x6820
#define VMCS_GUEST_PENDING_DBG 0x6822
#define VMCS_GUEST_SYSENTER_ESP 0x6824
#define VMCS_GUEST_SYSENTER_EIP 0x6826
#define VMCS_HOST_CR0 0x6c00
#define VMCS_HOST_CR3 0x6c02
#define VMCS_HOST_CR4 0x6c04
#define VMCS_HOST_FS_BASE 0x6c06
#define VMCS_HOST_GS_BASE 0x6c08
#define VMCS_HOST_TR_BASE 0x6c0a
#define VMCS_HOST_GDTR_BASE 0x6c0c
#define VMCS_HOST_IDTR_BASE 0x6c0e
#define VMCS_HOST_SYSENTER_ESP 0x6c10
#define VMCS_HOST_SYSENTER_EIP 0x6c12
#define VMCS_HOST_RSP 0x6c14
#define VMCS_HOST_RIP 0x6c16

/* Interruption information (Intel SDM 325462-093 Vol. 3C, 27.8.3, 27.9). */
#define VMX_INTR_VECTOR_MASK 0xff
#define VMX_INTR_TYPE_SHIFT 8
#define VMX_INTR_TYPE_MASK (7 << VMX_INTR_TYPE_SHIFT)
#define VMX_INTR_TYPE_EXT_INTR 0
#define VMX_INTR_TYPE_NMI 2
#define VMX_INTR_TYPE_HW_EXCEPTION 3
#define VMX_INTR_TYPE_SW_INTR 4
#define VMX_INTR_TYPE_PRIV_SW_EXCEPTION 5
#define VMX_INTR_TYPE_SW_EXCEPTION 6
#define VMX_INTR_TYPE_OTHER 7
#define VMX_INTR_ERROR_VALID (1U << 11)
#define VMX_INTR_NMI_UNBLOCKED (1U << 12)
#define VMX_INTR_VALID (1U << 31)

/* Guest interruptibility state (Intel SDM 325462-093 Vol. 3C, Table 27-3). */
#define VMX_BLOCKING_STI 1
#define VMX_BLOCKING_MOV_SS 2
#define VMX_BLOCKING_SMI 4
#define VMX_BLOCKING_NMI 8

/*
 * The debug exception bits of DR6 that #DB exit qualifications and the
 * pending debug exceptions field share: B0-B3, BD, BS, and RTM; the field
 * adds the enabled-breakpoint bit (Intel SDM 325462-093 Vol. 3C, Tables
 * 27-4 and 30-1).
 */
#define VMX_DB_BITS 0x1600f
#define VMX_PENDING_DBG_ENABLED_BP (1 << 12)
#define VMX_PENDING_DBG_RTM (1 << 16)

/* Access-rights fields (Intel SDM 325462-093 Vol. 3C, Table 27-2). */
#define VMX_AR_TYPE(ar) ((ar) & 0xf)
#define VMX_AR_S (1 << 4)
#define VMX_AR_DPL(ar) (((ar) >> 5) & 3)
#define VMX_AR_P (1 << 7)
#define VMX_AR_L (1 << 13)
#define VMX_AR_DB (1 << 14)
#define VMX_AR_G (1 << 15)
#define VMX_AR_UNUSABLE (1 << 16)
#define VMX_AR_RESERVED 0xfffe0f00

/* Guest activity states (Intel SDM 325462-093 Vol. 3C, 27.4.2). */
#define VMX_ACTIVITY_ACTIVE 0
#define VMX_ACTIVITY_HLT 1
#define VMX_ACTIVITY_SHUTDOWN 2
#define VMX_ACTIVITY_WAIT_SIPI 3

#define VMCS_VM_INSTRUCTION_ERROR 0x4400

/*
 * The VMCS fields TCG has, sorted by encoding (Intel SDM 325462-093 Vol. 3D,
 * Appendix B); a field's place here is its slot in env->vmx.vmcs and in the
 * VMCS region.
 */
static const uint16_t vmcs_fields[] = {
    0x0000, /* virtual-processor identifier */
    0x0002, /* posted-interrupt notification vector */
    0x0004, /* EPTP index */
    0x0008, /* last PID-pointer index */
    0x0800, /* guest ES selector */
    0x0802, /* guest CS selector */
    0x0804, /* guest SS selector */
    0x0806, /* guest DS selector */
    0x0808, /* guest FS selector */
    0x080a, /* guest GS selector */
    0x080c, /* guest LDTR selector */
    0x080e, /* guest TR selector */
    0x0810, /* guest interrupt status */
    0x0812, /* PML index */
    0x0c00, /* host ES selector */
    0x0c02, /* host CS selector */
    0x0c04, /* host SS selector */
    0x0c06, /* host DS selector */
    0x0c08, /* host FS selector */
    0x0c0a, /* host GS selector */
    0x0c0c, /* host TR selector */
    0x2000, /* I/O bitmap A address */
    0x2002, /* I/O bitmap B address */
    0x2004, /* MSR bitmaps address */
    0x2006, /* VM-exit MSR-store address */
    0x2008, /* VM-exit MSR-load address */
    0x200a, /* VM-entry MSR-load address */
    0x200c, /* executive-VMCS pointer */
    0x200e, /* PML address */
    0x2010, /* TSC offset */
    0x2012, /* virtual-APIC address */
    0x2014, /* APIC-access address */
    0x2016, /* posted-interrupt descriptor address */
    0x2018, /* VM-function controls */
    0x201a, /* EPT pointer */
    0x201c, /* EOI-exit bitmap 0 */
    0x201e, /* EOI-exit bitmap 1 */
    0x2020, /* EOI-exit bitmap 2 */
    0x2022, /* EOI-exit bitmap 3 */
    0x2024, /* EPTP-list address */
    0x2026, /* VMREAD-bitmap address */
    0x2028, /* VMWRITE-bitmap address */
    0x202a, /* virtualization-exception information address */
    0x202c, /* XSS-exiting bitmap */
    0x2032, /* TSC multiplier */
    0x2034, /* tertiary processor-based VM-execution controls */
    0x2042, /* PID-pointer table address */
    0x2400, /* guest-physical address */
    0x2800, /* VMCS link pointer */
    0x2802, /* guest IA32_DEBUGCTL */
    0x2804, /* guest IA32_PAT */
    0x2806, /* guest IA32_EFER */
    0x2808, /* guest IA32_PERF_GLOBAL_CTRL */
    0x280a, /* guest PDPTE0 */
    0x280c, /* guest PDPTE1 */
    0x280e, /* guest PDPTE2 */
    0x2810, /* guest PDPTE3 */
    0x2818, /* guest IA32_PKRS */
    0x2c00, /* host IA32_PAT */
    0x2c02, /* host IA32_EFER */
    0x2c04, /* host IA32_PERF_GLOBAL_CTRL */
    0x2c06, /* host IA32_PKRS */
    0x4000, /* pin-based VM-execution controls */
    0x4002, /* primary processor-based VM-execution controls */
    0x4004, /* exception bitmap */
    0x4006, /* page-fault error-code mask */
    0x4008, /* page-fault error-code match */
    0x400a, /* CR3-target count */
    0x400c, /* primary VM-exit controls */
    0x400e, /* VM-exit MSR-store count */
    0x4010, /* VM-exit MSR-load count */
    0x4012, /* VM-entry controls */
    0x4014, /* VM-entry MSR-load count */
    0x4016, /* VM-entry interruption-information field */
    0x4018, /* VM-entry exception error code */
    0x401a, /* VM-entry instruction length */
    0x401c, /* TPR threshold */
    0x401e, /* secondary processor-based VM-execution controls */
    0x4020, /* PLE_Gap */
    0x4022, /* PLE_Window */
    0x4400, /* VM-instruction error */
    0x4402, /* exit reason */
    0x4404, /* VM-exit interruption information */
    0x4406, /* VM-exit interruption error code */
    0x4408, /* IDT-vectoring information field */
    0x440a, /* IDT-vectoring error code */
    0x440c, /* VM-exit instruction length */
    0x440e, /* VM-exit instruction information */
    0x4800, /* guest ES limit */
    0x4802, /* guest CS limit */
    0x4804, /* guest SS limit */
    0x4806, /* guest DS limit */
    0x4808, /* guest FS limit */
    0x480a, /* guest GS limit */
    0x480c, /* guest LDTR limit */
    0x480e, /* guest TR limit */
    0x4810, /* guest GDTR limit */
    0x4812, /* guest IDTR limit */
    0x4814, /* guest ES access rights */
    0x4816, /* guest CS access rights */
    0x4818, /* guest SS access rights */
    0x481a, /* guest DS access rights */
    0x481c, /* guest FS access rights */
    0x481e, /* guest GS access rights */
    0x4820, /* guest LDTR access rights */
    0x4822, /* guest TR access rights */
    0x4824, /* guest interruptibility state */
    0x4826, /* guest activity state */
    0x4828, /* guest SMBASE */
    0x482a, /* guest IA32_SYSENTER_CS */
    0x482e, /* VMX-preemption timer value */
    0x4c00, /* host IA32_SYSENTER_CS */
    0x6000, /* CR0 guest/host mask */
    0x6002, /* CR4 guest/host mask */
    0x6004, /* CR0 read shadow */
    0x6006, /* CR4 read shadow */
    0x6008, /* CR3-target value 0 */
    0x600a, /* CR3-target value 1 */
    0x600c, /* CR3-target value 2 */
    0x600e, /* CR3-target value 3 */
    0x6400, /* exit qualification */
    0x6402, /* I/O RCX */
    0x6404, /* I/O RSI */
    0x6406, /* I/O RDI */
    0x6408, /* I/O RIP */
    0x640a, /* guest-linear address */
    0x6800, /* guest CR0 */
    0x6802, /* guest CR3 */
    0x6804, /* guest CR4 */
    0x6806, /* guest ES base */
    0x6808, /* guest CS base */
    0x680a, /* guest SS base */
    0x680c, /* guest DS base */
    0x680e, /* guest FS base */
    0x6810, /* guest GS base */
    0x6812, /* guest LDTR base */
    0x6814, /* guest TR base */
    0x6816, /* guest GDTR base */
    0x6818, /* guest IDTR base */
    0x681a, /* guest DR7 */
    0x681c, /* guest RSP */
    0x681e, /* guest RIP */
    0x6820, /* guest RFLAGS */
    0x6822, /* guest pending debug exceptions */
    0x6824, /* guest IA32_SYSENTER_ESP */
    0x6826, /* guest IA32_SYSENTER_EIP */
    0x6c00, /* host CR0 */
    0x6c02, /* host CR3 */
    0x6c04, /* host CR4 */
    0x6c06, /* host FS base */
    0x6c08, /* host GS base */
    0x6c0a, /* host TR base */
    0x6c0c, /* host GDTR base */
    0x6c0e, /* host IDTR base */
    0x6c10, /* host IA32_SYSENTER_ESP */
    0x6c12, /* host IA32_SYSENTER_EIP */
    0x6c14, /* host RSP */
    0x6c16, /* host RIP */
};

QEMU_BUILD_BUG_ON(ARRAY_SIZE(vmcs_fields) > VMX_VMCS_SLOTS);
QEMU_BUILD_BUG_ON(VMCS_FIELDS_OFFSET + 8 * VMX_VMCS_SLOTS > 4096);

/* The slot of a field by its encoding, with bit 0 clear, or -1. */
static int vmcs_slot(uint32_t encoding)
{
    int lo = 0, hi = ARRAY_SIZE(vmcs_fields) - 1;

    while (lo <= hi) {
        int mid = (lo + hi) / 2;

        if (vmcs_fields[mid] == encoding) {
            return mid;
        }
        if (vmcs_fields[mid] < encoding) {
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    return -1;
}

/* The highest index of a field, which IA32_VMX_VMCS_ENUM reports. */
static uint32_t vmcs_max_index(void)
{
    uint32_t max = 0;

    for (int i = 0; i < ARRAY_SIZE(vmcs_fields); i++) {
        max = MAX(max, VMCS_ENC_INDEX(vmcs_fields[i]));
    }
    return max;
}

/* A field of the current VMCS by its encoding, which must exist. */
uint64_t x86_vmcs_read(CPUX86State *env, uint32_t encoding)
{
    int slot = vmcs_slot(encoding);

    assert(slot >= 0);
    return env->vmx.vmcs[slot];
}

void x86_vmcs_write(CPUX86State *env, uint32_t encoding, uint64_t val)
{
    int slot = vmcs_slot(encoding);

    assert(slot >= 0);
    env->vmx.vmcs[slot] = val;
}

/*
 * The slot of a field that VMREAD and VMWRITE take, or -1: the high access
 * type exists for 64-bit fields only.
 */
static int vmcs_field_slot(uint64_t encoding)
{
    if (encoding >> 15 ||
        ((encoding & VMCS_ENC_HIGH) &&
         VMCS_ENC_WIDTH(encoding) != VMCS_WIDTH_64)) {
        return -1;
    }
    return vmcs_slot(encoding & ~VMCS_ENC_HIGH);
}

/*
 * VMREAD's value of a field: the high access type of a 64-bit field reads
 * its bits 63:32; narrower fields read zero-extended.
 */
static uint64_t vmcs_value(uint64_t encoding, uint64_t field)
{
    unsigned width = VMCS_ENC_WIDTH(encoding);

    if (encoding & VMCS_ENC_HIGH) {
        return field >> 32;
    }
    if (width == VMCS_WIDTH_16) {
        return field & 0xffff;
    }
    if (width == VMCS_WIDTH_32) {
        return field & 0xffffffff;
    }
    return field;
}

/*
 * A field after VMWRITE: the high access type writes bits 63:32 only; a
 * field longer than the value gets its high bits cleared. Access rights
 * keep their defined bits, as Linux 7.3's KVM does with them.
 */
static uint64_t vmcs_merge(uint64_t encoding, uint64_t field, uint64_t val)
{
    unsigned width = VMCS_ENC_WIDTH(encoding);

    if (encoding & VMCS_ENC_HIGH) {
        return (uint32_t)field | (uint64_t)(uint32_t)val << 32;
    }
    if (width == VMCS_WIDTH_16) {
        val &= 0xffff;
    } else if (width == VMCS_WIDTH_32) {
        val &= 0xffffffff;
    }
    if (encoding >= 0x4814 && encoding <= 0x4822) {
        val &= 0x1f0ff;
    }
    return val;
}

/* The current VMCS's fields to and from its VMCS region. */
static void vmcs_flush(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);
    uint64_t base = env->vmx.vmcs_ptr;

    if (base == ~0ULL) {
        return;
    }
    x86_stl_phys(cs, base + VMCS_LAUNCH_OFFSET, env->vmx.vmcs_launched);
    for (int i = 0; i < ARRAY_SIZE(vmcs_fields); i++) {
        x86_stq_phys(cs, base + VMCS_FIELDS_OFFSET + 8 * i, env->vmx.vmcs[i]);
    }
}

static void vmcs_load(CPUX86State *env, uint64_t base)
{
    CPUState *cs = env_cpu(env);

    env->vmx.vmcs_ptr = base;
    env->vmx.vmcs_launched = x86_ldl_phys(cs, base + VMCS_LAUNCH_OFFSET);
    for (int i = 0; i < ARRAY_SIZE(vmcs_fields); i++) {
        env->vmx.vmcs[i] = x86_ldq_phys(cs, base + VMCS_FIELDS_OFFSET + 8 * i);
    }
}

/*
 * VMsucceed, VMfailInvalid, and VMfailValid (Intel SDM 325462-093 Vol. 3C,
 * 33.2): the arithmetic flags all clear but CF, or ZF and the error number.
 */
static void vmx_succeed(CPUX86State *env)
{
    env->cc_src = 0;
}

static void vmx_fail_invalid(CPUX86State *env)
{
    env->cc_src = CC_C;
}

static void vmx_fail(CPUX86State *env, uint32_t error)
{
    if (env->vmx.vmcs_ptr == ~0ULL) {
        vmx_fail_invalid(env);
        return;
    }
    x86_vmcs_write(env, VMCS_VM_INSTRUCTION_ERROR, error);
    env->cc_src = CC_Z;
}

/*
 * The checks of VMX instructions in VMX root operation before their
 * operands: #UD outside VMX operation (the translator refuses real mode,
 * virtual-8086 mode, and compatibility mode), then #GP(0) at CPL > 0.
 */
static void vmx_check_root(CPUX86State *env, uintptr_t ra)
{
    if (!env->vmx.on) {
        raise_exception_ra(env, EXCP06_ILLOP, ra);
    }
    if (env->hflags & HF_CPL_MASK) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }
}

/* A VMXON, VMCLEAR, or VMPTRLD operand: 4 KiB aligned, within MAXPHYADDR. */
static bool vmx_region_valid(CPUX86State *env, uint64_t addr)
{
    return !(addr & 0xfff) && !(addr >> env_archcpu(env)->phys_bits);
}

/*
 * The CR0 and CR4 that VMX operation allows (Intel SDM 325462-093 Vol. 3D,
 * A.7 and A.8).
 */
static uint64_t vmx_cr_fixed0(int cr)
{
    return cr == 0 ? CR0_PG_MASK | CR0_NE_MASK | CR0_PE_MASK : CR4_VMXE_MASK;
}

static uint64_t vmx_cr_fixed1(CPUX86State *env, int cr)
{
    return cr == 0 ? 0xffffffff : ~cr4_reserved_bits(env);
}

static uint32_t vmx_proc2(CPUX86State *env);

bool x86_vmx_cr_valid(CPUX86State *env, int cr, uint64_t val)
{
    uint64_t fixed0 = vmx_cr_fixed0(cr);

    /*
     * Unrestricted guests may leave paging and protected mode
     * (Intel SDM 325462-093 Vol. 3C, 26.8).
     */
    if (cr == 0 && env->vmx.nonroot &&
        (vmx_proc2(env) & VMX_SECONDARY_EXEC_UNRESTRICTED_GUEST)) {
        fixed0 &= ~(CR0_PE_MASK | CR0_PG_MASK);
    }

    return (val & fixed0) == fixed0 && !(val & ~vmx_cr_fixed1(env, cr));
}

/*
 * A VMX instruction's memory operand, once the instruction's other checks
 * pass: an address that is not canonical in 64-bit mode faults, with
 * #SS(0) through SS and #GP(0) through the other segments (Intel SDM
 * 325462-093 Vol. 3C, 33.3).
 */
static void vmx_check_operand(CPUX86State *env, target_ulong ptr, int size,
                              int seg, uintptr_t ra)
{
    if ((env->hflags & HF_CS64_MASK) &&
        (!x86_canonical(env, ptr, true) ||
         !x86_canonical(env, ptr + size - 1, true))) {
        raise_exception_err_ra(env, seg == R_SS ? EXCP0C_STACK : EXCP0D_GPF,
                               0, ra);
    }
}

void HELPER(vmxon)(CPUX86State *env, target_ulong ptr, int seg)
{
    uintptr_t ra = GETPC();
    uint64_t addr;
    uint32_t rev;

    if (!(env->cr[4] & CR4_VMXE_MASK)) {
        raise_exception_ra(env, EXCP06_ILLOP, ra);
    }
    if (env->vmx.on) {
        if (env->hflags & HF_CPL_MASK) {
            raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
        }
        vmx_fail(env, VMXERR_VMXON_ROOT);
        return;
    }
    if ((env->hflags & HF_CPL_MASK) || x86_get_a20_mask(env) != -1 ||
        !x86_vmx_cr_valid(env, 0, env->cr[0]) ||
        !x86_vmx_cr_valid(env, 4, env->cr[4]) ||
        !(env->msr_ia32_feature_control & FEATURE_CONTROL_LOCKED) ||
        !(env->msr_ia32_feature_control &
          FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX)) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }
    vmx_check_operand(env, ptr, 8, seg, ra);
    addr = cpu_ldq_le_data_ra(env, ptr, ra);
    if (!vmx_region_valid(env, addr)) {
        vmx_fail_invalid(env);
        return;
    }
    rev = x86_ldl_phys(env_cpu(env), addr);
    if (rev != VMX_VMCS_REVISION) {
        vmx_fail_invalid(env);
        return;
    }
    env->vmx.on = true;
    env->vmx.vmxon_ptr = addr;
    env->vmx.vmcs_ptr = ~0ULL;
    vmx_succeed(env);
}

void HELPER(vmxoff)(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);

    vmx_check_root(env, GETPC());
    vmcs_flush(env);
    env->vmx.on = false;
    env->vmx.vmcs_ptr = ~0ULL;
    /* A20M applies again, to translations made without it too. */
    if (x86_get_a20_mask(env) != -1) {
        tlb_flush(cs);
    }
    if (env->vmx.init_pending) {
        env->vmx.init_pending = false;
        cpu_set_interrupt(cs, CPU_INTERRUPT_INIT);
    }
    vmx_succeed(env);
}

void HELPER(vmclear)(CPUX86State *env, target_ulong ptr, int seg)
{
    uintptr_t ra = GETPC();
    uint64_t addr;

    vmx_check_root(env, ra);
    vmx_check_operand(env, ptr, 8, seg, ra);
    addr = cpu_ldq_le_data_ra(env, ptr, ra);
    if (!vmx_region_valid(env, addr)) {
        vmx_fail(env, VMXERR_VMCLEAR_ADDR);
        return;
    }
    if (addr == env->vmx.vmxon_ptr) {
        vmx_fail(env, VMXERR_VMCLEAR_VMXON);
        return;
    }
    if (addr == env->vmx.vmcs_ptr) {
        env->vmx.vmcs_launched = 0;
        vmcs_flush(env);
        env->vmx.vmcs_ptr = ~0ULL;
    } else {
        x86_stl_phys(env_cpu(env), addr + VMCS_LAUNCH_OFFSET, 0);
    }
    vmx_succeed(env);
}

void HELPER(vmptrld)(CPUX86State *env, target_ulong ptr, int seg)
{
    uintptr_t ra = GETPC();
    uint64_t addr;
    uint32_t rev;

    vmx_check_root(env, ra);
    vmx_check_operand(env, ptr, 8, seg, ra);
    addr = cpu_ldq_le_data_ra(env, ptr, ra);
    if (!vmx_region_valid(env, addr)) {
        vmx_fail(env, VMXERR_VMPTRLD_ADDR);
        return;
    }
    if (addr == env->vmx.vmxon_ptr) {
        vmx_fail(env, VMXERR_VMPTRLD_VMXON);
        return;
    }
    rev = x86_ldl_phys(env_cpu(env), addr);
    if ((rev & 0x7fffffff) != VMX_VMCS_REVISION ||
        ((rev >> 31) && !(env->features[FEAT_VMX_SECONDARY_CTLS] &
                          VMX_SECONDARY_EXEC_SHADOW_VMCS))) {
        vmx_fail(env, VMXERR_VMPTRLD_REVISION);
        return;
    }
    if (addr != env->vmx.vmcs_ptr) {
        vmcs_flush(env);
        vmcs_load(env, addr);
    }
    vmx_succeed(env);
}

void HELPER(vmptrst)(CPUX86State *env, target_ulong ptr, int seg)
{
    uintptr_t ra = GETPC();

    vmx_check_root(env, ra);
    vmx_check_operand(env, ptr, 8, seg, ra);
    cpu_stq_le_data_ra(env, ptr, env->vmx.vmcs_ptr, ra);
    vmx_succeed(env);
}

/*
 * VMREAD and VMWRITE: the field encoding and the value or memory operand
 * are 64 bits in 64-bit mode and 32 bits outside IA-32e mode. A register
 * destination keeps its old value where VMREAD fails. In non-root
 * operation, where "VMCS shadowing" lets them through, they access the
 * shadow VMCS that the VMCS link pointer references, in its VMCS region
 * (Intel SDM 325462-093 Vol. 3C, 33.3).
 */
static bool vmx_check_vmcs(CPUX86State *env, uintptr_t ra)
{
    vmx_check_root(env, ra);
    if (env->vmx.nonroot ? x86_vmcs_read(env, VMCS_LINK_POINTER) == ~0ULL
                         : env->vmx.vmcs_ptr == ~0ULL) {
        vmx_fail_invalid(env);
        return false;
    }
    return true;
}

static hwaddr vmx_shadow_field(CPUX86State *env, int slot)
{
    return x86_vmcs_read(env, VMCS_LINK_POINTER) + VMCS_FIELDS_OFFSET +
           8 * slot;
}

static bool vmx_check_vmread(CPUX86State *env, target_ulong field,
                             uint64_t *val, uintptr_t ra)
{
    int slot;

    if (!vmx_check_vmcs(env, ra)) {
        return false;
    }
    slot = vmcs_field_slot(field);
    if (slot < 0) {
        vmx_fail(env, VMXERR_FIELD);
        return false;
    }
    *val = vmcs_value(field, env->vmx.nonroot ?
                      x86_ldq_phys(env_cpu(env), vmx_shadow_field(env, slot)) :
                      env->vmx.vmcs[slot]);
    return true;
}

target_ulong HELPER(vmread)(CPUX86State *env, target_ulong field,
                           target_ulong old)
{
    uint64_t val;

    if (!vmx_check_vmread(env, field, &val, GETPC())) {
        return old;
    }
    vmx_succeed(env);
    return val;
}

void HELPER(vmread_mem)(CPUX86State *env, target_ulong field,
                       target_ulong ptr, int seg)
{
    uintptr_t ra = GETPC();
    uint64_t val;

    if (!vmx_check_vmread(env, field, &val, ra)) {
        return;
    }
    vmx_check_operand(env, ptr, 8, seg, ra);
    if (env->hflags & HF_CS64_MASK) {
        cpu_stq_le_data_ra(env, ptr, val, ra);
    } else {
        cpu_stl_le_data_ra(env, ptr, val, ra);
    }
    vmx_succeed(env);
}

static void vmx_vmwrite(CPUX86State *env, target_ulong field, uint64_t val)
{
    CPUState *cs = env_cpu(env);
    int slot = vmcs_field_slot(field);

    if (slot < 0) {
        vmx_fail(env, VMXERR_FIELD);
        return;
    }
    if (VMCS_ENC_TYPE(field) == VMCS_TYPE_EXIT_INFO &&
        !(env->features[FEAT_VMX_MISC] & MSR_VMX_MISC_VMWRITE_VMEXIT)) {
        vmx_fail(env, VMXERR_READ_ONLY);
        return;
    }
    if (env->vmx.nonroot) {
        hwaddr addr = vmx_shadow_field(env, slot);

        x86_stq_phys(cs, addr, vmcs_merge(field, x86_ldq_phys(cs, addr), val));
    } else {
        env->vmx.vmcs[slot] = vmcs_merge(field, env->vmx.vmcs[slot], val);
    }
    vmx_succeed(env);
}

void HELPER(vmwrite)(CPUX86State *env, target_ulong field, target_ulong val)
{
    if (vmx_check_vmcs(env, GETPC())) {
        vmx_vmwrite(env, field, val);
    }
}

void HELPER(vmwrite_mem)(CPUX86State *env, target_ulong field,
                        target_ulong ptr, int seg)
{
    uintptr_t ra = GETPC();
    uint64_t val;

    if (!vmx_check_vmcs(env, ra)) {
        return;
    }
    vmx_check_operand(env, ptr, 8, seg, ra);
    if (env->hflags & HF_CS64_MASK) {
        val = cpu_ldq_le_data_ra(env, ptr, ra);
    } else {
        val = cpu_ldl_le_data_ra(env, ptr, ra);
    }
    vmx_vmwrite(env, field, val);
}

/*
 * The controls a VMX control MSR allows: bits 31:0 those that must be 1,
 * bits 63:32 those that may be; a control of the features word may be
 * either, others stay at their default (Intel SDM 325462-093 Vol. 3D,
 * A.2); the non-TRUE MSRs also keep the default1 controls at 1.
 */
static uint64_t vmx_ctl_msr(uint32_t features, uint32_t default1, bool true_msr)
{
    uint32_t must_be_one = default1 & ~features;

    if (!true_msr) {
        must_be_one |= default1;
    }
    return must_be_one | (uint64_t)(features | default1) << 32;
}

#define VMX_PINBASED_DEFAULT1 0x00000016
#define VMX_PROCBASED_DEFAULT1 0x0401e172
#define VMX_EXIT_DEFAULT1 0x00036dff
#define VMX_ENTRY_DEFAULT1 0x000011ff

/* IA32_VMX_MISC: VMX-preemption timer rate and CR3-target count. */
#define VMX_MISC_TIMER_RATE 5
#define VMX_MISC_CR3_TARGETS 4

static uint32_t vmx_exit_features(CPUX86State *env)
{
    uint32_t features = env->features[FEAT_VMX_EXIT_CTLS];

    if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM) {
        features |= VMX_VM_EXIT_HOST_ADDR_SPACE_SIZE;
    }
    return features;
}

/*
 * The VMX capability MSRs, from the CPU model's VMX features (Intel SDM
 * 325462-093 Vol. 3D, Appendix A); false where the MSR does not exist.
 */
bool x86_vmx_read_msr(CPUX86State *env, uint32_t index, uint64_t *val)
{
    uint64_t basic = env->features[FEAT_VMX_BASIC];
    uint64_t procbased = vmx_ctl_msr(env->features[FEAT_VMX_PROCBASED_CTLS],
                                     VMX_PROCBASED_DEFAULT1, false);
    uint32_t secondary = env->features[FEAT_VMX_SECONDARY_CTLS];
    bool has_secondary = procbased >> 32 &
                         VMX_CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
    bool true_ctls = basic & MSR_VMX_BASIC_TRUE_CTLS;

    if (!(env->features[FEAT_1_ECX] & CPUID_EXT_VMX)) {
        return false;
    }
    switch (index) {
    case MSR_IA32_VMX_BASIC:
        *val = VMX_VMCS_REVISION | 4096ULL << 32 | 6ULL << 50 |
               (basic & (MSR_VMX_BASIC_INS_OUTS | MSR_VMX_BASIC_TRUE_CTLS |
                         MSR_VMX_BASIC_ANY_ERRCODE |
                         MSR_VMX_BASIC_NESTED_EXCEPTION));
        return true;
    case MSR_IA32_VMX_PINBASED_CTLS:
    case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
        if (index == MSR_IA32_VMX_TRUE_PINBASED_CTLS && !true_ctls) {
            return false;
        }
        *val = vmx_ctl_msr(env->features[FEAT_VMX_PINBASED_CTLS],
                           VMX_PINBASED_DEFAULT1,
                           index == MSR_IA32_VMX_TRUE_PINBASED_CTLS);
        return true;
    case MSR_IA32_VMX_PROCBASED_CTLS:
    case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
        if (index == MSR_IA32_VMX_TRUE_PROCBASED_CTLS && !true_ctls) {
            return false;
        }
        *val = vmx_ctl_msr(env->features[FEAT_VMX_PROCBASED_CTLS],
                           VMX_PROCBASED_DEFAULT1,
                           index == MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
        return true;
    case MSR_IA32_VMX_EXIT_CTLS:
    case MSR_IA32_VMX_TRUE_EXIT_CTLS:
        if (index == MSR_IA32_VMX_TRUE_EXIT_CTLS && !true_ctls) {
            return false;
        }
        *val = vmx_ctl_msr(vmx_exit_features(env), VMX_EXIT_DEFAULT1,
                           index == MSR_IA32_VMX_TRUE_EXIT_CTLS);
        return true;
    case MSR_IA32_VMX_ENTRY_CTLS:
    case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
        if (index == MSR_IA32_VMX_TRUE_ENTRY_CTLS && !true_ctls) {
            return false;
        }
        *val = vmx_ctl_msr(env->features[FEAT_VMX_ENTRY_CTLS],
                           VMX_ENTRY_DEFAULT1,
                           index == MSR_IA32_VMX_TRUE_ENTRY_CTLS);
        return true;
    case MSR_IA32_VMX_MISC:
        *val = VMX_MISC_TIMER_RATE | VMX_MISC_CR3_TARGETS << 16 |
               (env->features[FEAT_VMX_MISC] &
                (MSR_VMX_MISC_STORE_LMA | MSR_VMX_MISC_ACTIVITY_HLT |
                 MSR_VMX_MISC_ACTIVITY_SHUTDOWN |
                 MSR_VMX_MISC_ACTIVITY_WAIT_SIPI |
                 MSR_VMX_MISC_VMWRITE_VMEXIT | MSR_VMX_MISC_ZERO_LEN_INJECT));
        return true;
    case MSR_IA32_VMX_CR0_FIXED0:
    case MSR_IA32_VMX_CR4_FIXED0:
        *val = vmx_cr_fixed0(index == MSR_IA32_VMX_CR0_FIXED0 ? 0 : 4);
        return true;
    case MSR_IA32_VMX_CR0_FIXED1:
    case MSR_IA32_VMX_CR4_FIXED1:
        *val = vmx_cr_fixed1(env, index == MSR_IA32_VMX_CR0_FIXED1 ? 0 : 4);
        return true;
    case MSR_IA32_VMX_VMCS_ENUM:
        *val = vmcs_max_index() << 1;
        return true;
    case MSR_IA32_VMX_PROCBASED_CTLS2:
        if (!has_secondary) {
            return false;
        }
        *val = vmx_ctl_msr(secondary, 0, false);
        return true;
    case MSR_IA32_VMX_EPT_VPID_CAP:
        if (!has_secondary || !(secondary & (VMX_SECONDARY_EXEC_ENABLE_EPT |
                                             VMX_SECONDARY_EXEC_ENABLE_VPID))) {
            return false;
        }
        *val = env->features[FEAT_VMX_EPT_VPID_CAPS];
        if (secondary & VMX_SECONDARY_EXEC_ENABLE_EPT) {
            *val |= MSR_VMX_EPT_UC | MSR_VMX_EPT_WB;
        }
        return true;
    case MSR_IA32_VMX_VMFUNC:
        if (!has_secondary || !(secondary & VMX_SECONDARY_EXEC_ENABLE_VMFUNC)) {
            return false;
        }
        *val = env->features[FEAT_VMX_VMFUNC];
        return true;
    case MSR_IA32_VMX_PROCBASED_CTLS3:
        /*
         * All 64 bits are allowed 1-settings (Intel SDM 325462-093 Vol. 3D,
         * A.3.4).
         */
        if (!(procbased >> 32 & VMX_CPU_BASED_ACTIVATE_TERTIARY_CONTROLS)) {
            return false;
        }
        *val = env->features[FEAT_VMX_TERTIARY_CTLS];
        return true;
    default:
        return false;
    }
}

/*
 * IA32_FEATURE_CONTROL, which firmware locks: the lock, VMX outside SMX,
 * and LMCE where the processor has them (Intel SDM 325462-093 Vol. 4,
 * Table 2-2).
 */
bool x86_feature_control_exists(CPUX86State *env)
{
    return IS_INTEL_CPU(env) ||
           (env->features[FEAT_1_ECX] & CPUID_EXT_VMX);
}

bool x86_feature_control_write(CPUX86State *env, uint64_t val)
{
    uint64_t valid = FEATURE_CONTROL_LOCKED;

    if (env->features[FEAT_1_ECX] & CPUID_EXT_VMX) {
        valid |= FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;
    }
    if (env->mcg_cap & MCG_LMCE_P) {
        valid |= FEATURE_CONTROL_LMCE;
    }
    if ((env->msr_ia32_feature_control & FEATURE_CONTROL_LOCKED) ||
        (val & ~valid)) {
        return false;
    }
    env->msr_ia32_feature_control = val;
    return true;
}

/*
 * INIT is blocked in VMX root operation (Intel SDM 325462-093 Vol. 3C,
 * 26.8): it waits for VMXOFF, or a VM entry, after which it exits.
 */
bool x86_vmx_holds_init(CPUX86State *env)
{
    if (!env->vmx.on || env->vmx.nonroot) {
        return false;
    }
    env->vmx.init_pending = true;
    return true;
}

/*
 * SMM is outside VMX operation; RSM returns to it (Intel SDM 325462-093
 * Vol. 3C, 34.14.1 and 34.14.2).
 */
void x86_vmx_smm_enter(CPUX86State *env)
{
    env->vmx.smm_on = env->vmx.on;
    env->vmx.smm_nonroot = env->vmx.nonroot;
    env->vmx.on = false;
    env->vmx.nonroot = false;
}

void x86_vmx_smm_leave(CPUX86State *env)
{
    env->vmx.on = env->vmx.smm_on;
    env->vmx.nonroot = env->vmx.smm_nonroot;
    env->vmx.smm_on = false;
    env->vmx.smm_nonroot = false;
}

/*
 * VMX non-root operation: VM entries, VM exits, and what causes the exits
 * (Intel SDM 325462-093 Vol. 3C, Chapters 26 to 30).
 */

#define VMCS(f) x86_vmcs_read(env, VMCS_##f)
#define VMCS_SET(f, v) x86_vmcs_write(env, VMCS_##f, v)

static uint32_t vmx_proc2(CPUX86State *env)
{
    return VMCS(PROC_CONTROLS) & VMX_CPU_BASED_ACTIVATE_SECONDARY_CONTROLS ?
           VMCS(PROC2_CONTROLS) : 0;
}

static uint64_t vmx_proc3(CPUX86State *env)
{
    return VMCS(PROC_CONTROLS) & VMX_CPU_BASED_ACTIVATE_TERTIARY_CONTROLS ?
           VMCS(PROC3_CONTROLS) : 0;
}

/* VMX access rights from and to QEMU's descriptor flags. */
static uint32_t vmx_ar(const SegmentCache *sc)
{
    if (!(sc->flags & DESC_P_MASK)) {
        return VMX_AR_UNUSABLE | ((sc->flags >> DESC_DPL_SHIFT) & 3) << 5;
    }
    return ((sc->flags >> DESC_TYPE_SHIFT) & 0xff) |
           ((sc->flags >> 20) & 0xf) << 12;
}

static uint32_t vmx_flags(uint32_t ar)
{
    if (ar & VMX_AR_UNUSABLE) {
        return VMX_AR_DPL(ar) << DESC_DPL_SHIFT;
    }
    return (ar & 0xff) << DESC_TYPE_SHIFT | ((ar >> 12) & 0xf) << 20;
}

/*
 * A VM exit: the exit information goes to the current VMCS, then the
 * main loop saves the guest's state and loads the host's (do_vmexit).
 */
G_NORETURN void x86_vmx_exit_full(CPUX86State *env, uint32_t reason,
                                  uint64_t qual, uint32_t intr_info,
                                  uint32_t intr_error, uintptr_t ra)
{
    CPUState *cs = env_cpu(env);

    if (ra) {
        cpu_restore_state(cs, ra);
    }
    qemu_log_mask(CPU_LOG_INT, "VMX exit %u qual 0x%" PRIx64 " rip "
                  TARGET_FMT_lx "\n", reason, qual, env->eip);
    VMCS_SET(EXIT_REASON, reason);
    VMCS_SET(EXIT_QUALIFICATION, qual);
    VMCS_SET(EXIT_INTR_INFO, intr_info);
    VMCS_SET(EXIT_INTR_ERROR, intr_error);
    VMCS_SET(EXIT_INSN_LEN, env->svm_insn_len);
    env->vmx.exit_nmi = reason == VMX_EXIT_EXCEPTION_NMI &&
                        (intr_info & VMX_INTR_TYPE_MASK) ==
                        VMX_INTR_TYPE_NMI << VMX_INTR_TYPE_SHIFT;
    cs->exception_index = EXCP_VMEXIT;
    env->old_exception = -1;
    cpu_loop_exit(cs);
}

G_NORETURN void x86_vmx_exit(CPUX86State *env, uint32_t reason,
                             uint64_t qual, uintptr_t ra)
{
    x86_vmx_exit_full(env, reason, qual, 0, 0, ra);
}

/* The MSR bitmaps (Intel SDM 325462-093 Vol. 3C, 27.6.9). */
static bool vmx_msr_exits(CPUX86State *env, uint32_t msr, bool write)
{
    uint64_t base = VMCS(MSR_BITMAP);
    uint32_t offset = write ? 2048 : 0;

    if (!(VMCS(PROC_CONTROLS) & VMX_CPU_BASED_USE_MSR_BITMAPS)) {
        return true;
    }
    if (msr >= 0xc0000000 && msr <= 0xc0001fff) {
        offset += 1024;
        msr -= 0xc0000000;
    } else if (msr > 0x1fff) {
        return true;
    }
    return x86_ldub_phys(env_cpu(env), base + offset + msr / 8) &
           (1 << (msr & 7));
}

/*
 * The I/O bitmaps, or unconditional I/O exiting (Intel SDM 325462-093 Vol. 3C,
 * 27.6.4).
 */
static bool vmx_io_exits(CPUX86State *env, uint32_t port, int size)
{
    uint32_t proc = VMCS(PROC_CONTROLS);

    if (!(proc & VMX_CPU_BASED_USE_IO_BITMAPS)) {
        return proc & VMX_CPU_BASED_UNCOND_IO_EXITING;
    }
    for (int i = 0; i < size; i++) {
        uint32_t p = port + i;
        uint64_t base;

        if (p > 0xffff) {
            return true;
        }
        base = p < 0x8000 ? VMCS(IO_BITMAP_A) : VMCS(IO_BITMAP_B);
        if (x86_ldub_phys(env_cpu(env), base + (p & 0x7fff) / 8) &
            (1 << (p & 7))) {
            return true;
        }
    }
    return false;
}

/*
 * An I/O instruction's exit: the qualification gives its size,
 * direction, string and REP forms, and port; a string form also the
 * linear address of its memory operand and the address size and segment
 * in the instruction information (Intel SDM 325462-093 Vol. 3C, Table
 * 30-5 and 30.2.5).
 */
void x86_vmx_check_io(CPUX86State *env, uint32_t port, uint32_t svm_flags,
                      uintptr_t ra)
{
    int size = (svm_flags & SVM_IOIO_SIZE_MASK) >> SVM_IOIO_SIZE_SHIFT;
    uint64_t qual;
    int asize = 0;

    size = size == 4 ? 4 : size == 2 ? 2 : 1;
    if (!vmx_io_exits(env, port, size)) {
        return;
    }
    qual = (size - 1) | (uint64_t)port << 16;
    if (svm_flags & SVM_IOIO_TYPE_MASK) {
        qual |= 1 << 3;
    }
    if (svm_flags & SVM_IOIO_STR_MASK) {
        bool in = svm_flags & SVM_IOIO_TYPE_MASK;
        int seg = in ? R_ES : (svm_flags >> SVM_IOIO_SEG_SHIFT) & 7;
        target_ulong offset = env->regs[in ? R_EDI : R_ESI];

        asize = (svm_flags >> SVM_IOIO_ASIZE_SHIFT) & 7;
        asize = asize == 4 ? 2 : asize == 2 ? 1 : 0;
        if (asize == 0) {
            offset &= 0xffff;
        } else if (asize == 1) {
            offset &= 0xffffffff;
        }
        qual |= 1 << 4;
        VMCS_SET(GUEST_LINEAR_ADDR, env->segs[seg].base + offset);
        VMCS_SET(EXIT_INSN_INFO, asize << 7 | seg << 15);
    }
    if (svm_flags & SVM_IOIO_REP_MASK) {
        qual |= 1 << 5;
    }
    if (svm_flags & SVM_IOIO_IMM_MASK) {
        qual |= 1 << 6;
    }
    x86_vmx_exit(env, VMX_EXIT_IO, qual, ra);
}

/*
 * Whether an exception exits, by the exception bitmap and, for #PF, the
 * page-fault error-code mask and match (Intel SDM 325462-093 Vol. 3C, 27.6.3).
 */
bool x86_vmx_exception_exits(CPUX86State *env, int vector,
                             uint32_t error_code)
{
    uint32_t bitmap = VMCS(EXCEPTION_BITMAP);

    if (vector == EXCP0E_PAGE) {
        bool match = (error_code & VMCS(PF_ERROR_MASK)) ==
                     VMCS(PF_ERROR_MATCH);

        return ((bitmap >> EXCP0E_PAGE) & 1) == match;
    }
    return vector < 32 && (bitmap >> vector) & 1;
}

static void vmx_exception_exit(CPUX86State *env, int vector,
                               uint32_t error_code, uintptr_t ra)
{
    uint32_t type = env->vmx.soft_exception ? env->vmx.soft_exception
                                            : VMX_INTR_TYPE_HW_EXCEPTION;
    uint32_t info = vector | type << VMX_INTR_TYPE_SHIFT | VMX_INTR_VALID;
    uint64_t qual = 0;

    /* What does not exit keeps its type for the IDT-vectoring information. */
    if (!x86_vmx_exception_exits(env, vector, error_code)) {
        return;
    }
    env->vmx.soft_exception = 0;
    if (type == VMX_INTR_TYPE_HW_EXCEPTION &&
        exception_has_error_code(vector) && (env->cr[0] & CR0_PE_MASK)) {
        info |= VMX_INTR_ERROR_VALID;
    } else {
        error_code = 0;
    }
    if (vector == EXCP0E_PAGE) {
        qual = env->vmx.exception_qual;
    } else if (vector == EXCP01_DB && type == VMX_INTR_TYPE_HW_EXCEPTION) {
        /* DR6 keeps its value (Intel SDM 325462-093 Vol. 3C, 30.1). */
        qual = env->db_payload & VMX_DB_BITS;
        env->db_payload = 0;
    }
    x86_vmx_exit_full(env, VMX_EXIT_EXCEPTION_NMI, qual, info, error_code,
                      ra);
}

/*
 * CR3 loads that match a CR3-target value do not exit (Intel SDM 325462-093
 * Vol. 3C, 28.1.3).
 */
static bool vmx_cr3_target(CPUX86State *env, uint64_t cr3)
{
    uint32_t count = MIN(VMCS(CR3_TARGET_COUNT), VMX_MISC_CR3_TARGETS);

    for (uint32_t i = 0; i < count; i++) {
        if (x86_vmcs_read(env, VMCS_CR3_TARGET(i)) == cr3) {
            return true;
        }
    }
    return false;
}

/*
 * MOV to CR0, CR3, CR4, or CR8 in non-root operation: the exit, or the
 * value the processor writes, keeping the bits the guest/host masks own
 * (Intel SDM 325462-093 Vol. 3C, 28.1.3 and 28.3). gpr is the source
 * register's number.
 */
uint64_t x86_vmx_cr_write(CPUX86State *env, int cr, uint64_t val, int gpr,
                          uintptr_t ra)
{
    uint64_t qual = cr | (uint64_t)gpr << 8;
    uint64_t mask, shadow;

    switch (cr) {
    case 0:
    case 4:
        mask = cr ? VMCS(CR4_MASK) : VMCS(CR0_MASK);
        shadow = cr ? VMCS(CR4_SHADOW) : VMCS(CR0_SHADOW);
        if ((val ^ shadow) & mask) {
            x86_vmx_exit(env, VMX_EXIT_CR_ACCESS, qual, ra);
        }
        return (val & ~mask) | (env->cr[cr] & mask);
    case 3:
        if ((VMCS(PROC_CONTROLS) & VMX_CPU_BASED_CR3_LOAD_EXITING) &&
            !vmx_cr3_target(env, val)) {
            x86_vmx_exit(env, VMX_EXIT_CR_ACCESS, qual, ra);
        }
        return val;
    case 8:
        if (VMCS(PROC_CONTROLS) & VMX_CPU_BASED_CR8_LOAD_EXITING) {
            x86_vmx_exit(env, VMX_EXIT_CR_ACCESS, qual, ra);
        }
        return val;
    default:
        return val;
    }
}

/* MOV from CR0 or CR4 reads the read shadow's bits where masks own them. */
target_ulong x86_vmx_cr_read(CPUX86State *env, int cr)
{
    uint64_t mask = cr ? VMCS(CR4_MASK) : VMCS(CR0_MASK);
    uint64_t shadow = cr ? VMCS(CR4_SHADOW) : VMCS(CR0_SHADOW);

    return (env->cr[cr] & ~mask) | (shadow & mask);
}

/*
 * MOV from and to CR8 under "use TPR shadow" access VTPR, at offset 80H
 * of the virtual-APIC page, rather than the TPR (Intel SDM 325462-093
 * Vol. 3C, 32.1.1 and 32.3).
 */
bool x86_vmx_tpr_shadow(CPUX86State *env)
{
    return env->vmx.nonroot &&
           (VMCS(PROC_CONTROLS) & VMX_CPU_BASED_TPR_SHADOW);
}

target_ulong x86_vmx_read_cr8(CPUX86State *env)
{
    return x86_ldub_phys(env_cpu(env), VMCS(VIRTUAL_APIC_ADDR) + 0x80) >> 4;
}

/*
 * Without virtual-interrupt delivery, TPR virtualization calls for a
 * TPR-below-threshold VM exit where VTPR[7:4] is below the TPR threshold
 * (Intel SDM 325462-093 Vol. 3C, 32.1.2).
 */
static bool vmx_tpr_below_threshold(CPUX86State *env)
{
    uint8_t vtpr = x86_ldub_phys(env_cpu(env), VMCS(VIRTUAL_APIC_ADDR) + 0x80);

    return !(vmx_proc2(env) & VMX_SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY) &&
           vtpr >> 4 < (VMCS(TPR_THRESHOLD) & 0xf);
}

/*
 * A trap-like VM exit after the instruction at RA, whose single-step trap
 * stays pending (Intel SDM 325462-093 Vol. 3C, 30.3.4).
 */
static G_NORETURN void vmx_trap_exit(CPUX86State *env, uint32_t reason,
                                     uint64_t qual, uintptr_t ra)
{
    cpu_restore_state(env_cpu(env), ra);
    x86_pmu_restored_retired(env);
    env->eip += env->svm_insn_len;
    do_end_instruction(env);
    env->vmx.exit_pending_dbg = x86_step_trap(env, false);
    x86_vmx_exit(env, reason, qual, 0);
}

/*
 * Virtual-interrupt delivery's state (Intel SDM 325462-093 Vol. 3C, 32.1.1
 * and 27.4.2): VPPR, VISR, and VIRR on the virtual-APIC page, the bit of
 * vector x of the latter two at bit x & 1FH of the 32 bits at their base
 * plus (x & E0H) >> 1, and RVI and SVI, the low and high bytes of the guest
 * interrupt status, which stays in the VMCS.
 */
#define VMX_VAPIC_VPPR 0xa0
#define VMX_VAPIC_VEOI 0xb0
#define VMX_VAPIC_VISR 0x100
#define VMX_VAPIC_VIRR 0x200
#define VMX_VAPIC_VICR_LO 0x300

static void vmx_vapic_set_bit(CPUX86State *env, hwaddr base, int vector,
                              bool set)
{
    CPUState *cs = env_cpu(env);
    hwaddr addr = VMCS(VIRTUAL_APIC_ADDR) + base + ((vector & 0xe0) >> 1);
    uint32_t bit = 1U << (vector & 0x1f);
    uint32_t val = x86_ldl_phys(cs, addr);

    x86_stl_phys(cs, addr, set ? val | bit : val & ~bit);
}

/* The highest vector set in VISR or VIRR, else 0. */
static int vmx_vapic_highest(CPUX86State *env, hwaddr base)
{
    CPUState *cs = env_cpu(env);
    hwaddr vapic = VMCS(VIRTUAL_APIC_ADDR);

    for (int i = 7; i >= 0; i--) {
        uint32_t val = x86_ldl_phys(cs, vapic + base + i * 0x10);

        if (val) {
            return i * 32 + 31 - clz32(val);
        }
    }
    return 0;
}

static void vmx_set_rvi(CPUX86State *env, int rvi)
{
    VMCS_SET(GUEST_INTR_STATUS, (VMCS(GUEST_INTR_STATUS) & 0xff00) | rvi);
}

static void vmx_set_svi(CPUX86State *env, int svi)
{
    VMCS_SET(GUEST_INTR_STATUS, (VMCS(GUEST_INTR_STATUS) & 0xff) | svi << 8);
}

/* PPR virtualization (Intel SDM 325462-093 Vol. 3C, 32.1.3). */
static void vmx_ppr_virtualize(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);
    hwaddr vapic = VMCS(VIRTUAL_APIC_ADDR);
    uint8_t vtpr = x86_ldub_phys(cs, vapic + 0x80);
    uint8_t svi = VMCS(GUEST_INTR_STATUS) >> 8;

    x86_stl_phys(cs, vapic + VMX_VAPIC_VPPR,
                 vtpr >> 4 >= svi >> 4 ? vtpr : svi & 0xf0);
}

/*
 * The evaluation of pending virtual interrupts (Intel SDM 325462-093 Vol.
 * 3C, 32.2.1), which recognizes one, without "interrupt-window exiting",
 * where RVI[7:4] is above VPPR[7:4].
 */
static void vmx_vintr_evaluate(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);
    uint8_t rvi = VMCS(GUEST_INTR_STATUS);
    uint8_t vppr = x86_ldub_phys(cs, VMCS(VIRTUAL_APIC_ADDR) + VMX_VAPIC_VPPR);

    env->vmx.vintr_pending =
        !(VMCS(PROC_CONTROLS) & VMX_CPU_BASED_VIRTUAL_INTR_PENDING) &&
        rvi >> 4 > vppr >> 4;
    if (env->vmx.vintr_pending) {
        cpu_set_interrupt(cs, CPU_INTERRUPT_VMX);
        qatomic_set(&cs->neg.icount_decr.u16.high, -1);
    }
}

/*
 * Virtual-interrupt delivery (Intel SDM 325462-093 Vol. 3C, 32.2.2): the
 * vector of RVI goes in service and to the guest through its IDT, as an
 * external interrupt would.
 */
static void vmx_vintr_deliver(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);
    int vector = VMCS(GUEST_INTR_STATUS) & 0xff;

    vmx_vapic_set_bit(env, VMX_VAPIC_VISR, vector, true);
    vmx_set_svi(env, vector);
    x86_stl_phys(cs, VMCS(VIRTUAL_APIC_ADDR) + VMX_VAPIC_VPPR, vector & 0xf0);
    vmx_vapic_set_bit(env, VMX_VAPIC_VIRR, vector, false);
    vmx_set_rvi(env, vmx_vapic_highest(env, VMX_VAPIC_VIRR));
    env->vmx.vintr_pending = false;
    do_interrupt_x86_hardirq(env, vector, 1);
    cs->exception_index = -1;
}

/*
 * TPR virtualization after the instruction at RA wrote VTPR (Intel SDM
 * 325462-093 Vol. 3C, 32.1.2).
 */
static void vmx_tpr_virtualize(CPUX86State *env, uintptr_t ra)
{
    if (vmx_proc2(env) & VMX_SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY) {
        vmx_ppr_virtualize(env);
        vmx_vintr_evaluate(env);
    } else if (vmx_tpr_below_threshold(env)) {
        vmx_trap_exit(env, VMX_EXIT_TPR_BELOW_THRESHOLD, 0, ra);
    }
}

/*
 * EOI virtualization (Intel SDM 325462-093 Vol. 3C, 32.1.4), whose EOI-
 * induced VM exits, for vectors the EOI-exit bitmap names, are trap-like.
 */
static void vmx_eoi_virtualize(CPUX86State *env, uintptr_t ra)
{
    int vector = VMCS(GUEST_INTR_STATUS) >> 8;
    uint64_t bitmap = x86_vmcs_read(env, VMCS_EOI_EXIT_BITMAP(vector >> 6));

    vmx_vapic_set_bit(env, VMX_VAPIC_VISR, vector, false);
    vmx_set_svi(env, vmx_vapic_highest(env, VMX_VAPIC_VISR));
    vmx_ppr_virtualize(env);
    if (bitmap & 1ULL << (vector & 63)) {
        vmx_trap_exit(env, VMX_EXIT_EOI_INDUCED, vector, ra);
    }
    vmx_vintr_evaluate(env);
}

/* Self-IPI virtualization (Intel SDM 325462-093 Vol. 3C, 32.1.5). */
static void vmx_self_ipi_virtualize(CPUX86State *env, int vector)
{
    vmx_vapic_set_bit(env, VMX_VAPIC_VIRR, vector, true);
    vmx_set_rvi(env, MAX(VMCS(GUEST_INTR_STATUS) & 0xff, vector));
    vmx_vintr_evaluate(env);
}

/*
 * Virtual-interrupt posting (Intel SDM 325462-093 Vol. 3C, 32.1.6.1): the
 * request bit of VECTOR, then the outstanding-notification bit where it and
 * suppress-notify are clear, each set atomically in the 64-byte PID, which
 * other processors write too. True where the notification is due, NV and
 * NDST its vector and destination.
 */
static bool vmx_pid_post(CPUX86State *env, hwaddr pid, int vector,
                         uint8_t *nv, uint32_t *ndst)
{
    CPUState *cs = env_cpu(env);
    hwaddr len = 64;
    uint32_t *desc = address_space_map(cs->as, pid, &len, true,
                                       MEMTXATTRS_UNSPECIFIED);
    uint32_t old;
    bool notify;

    if (!desc || len < 64) {
        if (desc) {
            address_space_unmap(cs->as, desc, len, false, 0);
        }
        x86_stl_phys(cs, pid + vector / 32 * 4,
                     x86_ldl_phys(cs, pid + vector / 32 * 4) |
                     1u << (vector % 32));
        old = x86_ldl_phys(cs, pid + 32);
        notify = !(old & 3);
        if (notify) {
            x86_stl_phys(cs, pid + 32, old | 1);
        }
        *nv = old >> 16;
        *ndst = x86_ldl_phys(cs, pid + 36);
        return notify;
    }
    qatomic_or(&desc[vector / 32], cpu_to_le32(1u << (vector % 32)));
    do {
        old = qatomic_read(&desc[8]);
        notify = !(le32_to_cpu(old) & 3);
    } while (notify &&
             qatomic_cmpxchg(&desc[8], old, old | cpu_to_le32(1)) != old);
    *nv = le32_to_cpu(old) >> 16;
    *ndst = le32_to_cpu(qatomic_read(&desc[9]));
    address_space_unmap(cs->as, desc, len, true, 64);
    return notify;
}

/*
 * IPI virtualization (Intel SDM 325462-093 Vol. 3C, 32.1.6.2): the virtual
 * IPI of VECTOR to virtual APIC ID ID posts VECTOR in the PID the ID-th
 * entry of the PID-pointer table names, and the notification it may call
 * for is an IPI of NV to NDST, NDST[15:8] where the local APIC is in xAPIC
 * mode. A vector below 10H, an ID past the last PID-pointer index, and an
 * entry not valid or with bits beyond the address width make an APIC-write
 * VM exit for 300H instead.
 */
static void vmx_ipi_virtualize(CPUX86State *env, int vector, uint32_t id,
                               uintptr_t ra)
{
    APICCommonState *apic = env_archcpu(env)->apic_state;
    uint64_t entry;
    uint32_t ndst;
    uint8_t nv;

    if (vector < 16 || id > VMCS(LAST_PID_INDEX)) {
        vmx_trap_exit(env, VMX_EXIT_APIC_WRITE, VMX_VAPIC_VICR_LO, ra);
    }
    entry = x86_ldq_phys(env_cpu(env), VMCS(PID_TABLE_ADDR) + 8ULL * id);
    if ((entry & 0x3f) != 1 || entry >> env_archcpu(env)->phys_bits) {
        vmx_trap_exit(env, VMX_EXIT_APIC_WRITE, VMX_VAPIC_VICR_LO, ra);
    }
    if (vmx_pid_post(env, entry & ~0x3fULL, vector, &nv, &ndst)) {
        BQL_LOCK_GUARD();
        apic_send_fixed_ipi(is_x2apic_mode(apic) ? ndst : ndst >> 8 & 0xff,
                            nv);
    }
}

/*
 * Posted-interrupt processing, for an external interrupt of the
 * notification vector (Intel SDM 325462-093 Vol. 3C, 32.6): the
 * outstanding-notification bit of the descriptor, which other processors
 * write too, clears atomically, the local APIC takes an EOI, the requests
 * of the descriptor move atomically to VIRR and RVI, and pending virtual
 * interrupts are evaluated.
 */
static void vmx_posted_interrupts(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);
    hwaddr vapic = VMCS(VIRTUAL_APIC_ADDR);
    hwaddr len = 64;
    uint32_t *desc = address_space_map(cs->as, VMCS(PI_DESC_ADDR), &len,
                                       true, MEMTXATTRS_UNSPECIFIED);
    int rvi = VMCS(GUEST_INTR_STATUS) & 0xff;

    if (desc && len == 64) {
        qatomic_and(&desc[8], cpu_to_le32(~1U));
    }
    apic_write_eoi(env_archcpu(env)->apic_state);
    for (int i = 0; desc && len == 64 && i < 8; i++) {
        uint32_t pir = le32_to_cpu(qatomic_xchg(&desc[i], 0));
        hwaddr virr = vapic + VMX_VAPIC_VIRR + i * 0x10;

        if (pir) {
            x86_stl_phys(cs, virr, x86_ldl_phys(cs, virr) | pir);
            rvi = MAX(rvi, i * 32 + 31 - clz32(pir));
        }
    }
    if (desc) {
        address_space_unmap(cs->as, desc, len, true, len);
    }
    vmx_set_rvi(env, rvi);
    vmx_vintr_evaluate(env);
}

/*
 * MOV to CR8 leaves VTPR its source's bits 3:0 in bits 7:4 (Intel SDM
 * 325462-093 Vol. 3C, 32.3).
 */
void x86_vmx_write_cr8(CPUX86State *env, target_ulong val, uintptr_t ra)
{
    CPUState *cs = env_cpu(env);

    x86_stl_phys(cs, VMCS(VIRTUAL_APIC_ADDR) + 0x80, (val & 0xf) << 4);
    vmx_tpr_virtualize(env, ra);
}

/*
 * The access types of APIC-access VM exits (Intel SDM 325462-093 Vol. 3C,
 * Table 30-6).
 */
#define VMX_APIC_ACCESS_READ 0
#define VMX_APIC_ACCESS_WRITE 1
#define VMX_APIC_ACCESS_FETCH 2
#define VMX_APIC_ACCESS_DELIVERY 3

/*
 * The 16-byte lines of the APIC-access page whose accesses "APIC-register
 * virtualization" virtualizes, as bits by offset over 16: for writes, ID,
 * TPR, EOI, LDR, DFR, SVR, ESR, ICR, the LVT, the timer's initial count, and
 * its divide configuration; for reads, also version, ISR, TMR, and IRR
 * (Intel SDM 325462-093 Vol. 3C, 32.4.2 and 32.4.3.1).
 */
#define VMX_APIC_LINE(offset) (1ULL << ((offset) >> 4))
#define VMX_APIC_LINES(first, last) \
    ((VMX_APIC_LINE(last) << 1) - VMX_APIC_LINE(first))
#define VMX_APIC_REG_VIRT_WRITES \
    (VMX_APIC_LINE(0x20) | VMX_APIC_LINE(0x80) | VMX_APIC_LINE(0xb0) | \
     VMX_APIC_LINES(0xd0, 0xf0) | VMX_APIC_LINE(0x280) | \
     VMX_APIC_LINES(0x300, 0x380) | VMX_APIC_LINE(0x3e0))
#define VMX_APIC_REG_VIRT_READS \
    (VMX_APIC_REG_VIRT_WRITES | VMX_APIC_LINE(0x30) | \
     VMX_APIC_LINES(0x100, 0x270))

/*
 * The APIC-access page (Intel SDM 325462-093 Vol. 3C, 32.4), whose data
 * accesses TLB entries send to the AVIC address space's page. With "use
 * TPR shadow", accesses of 32 bits or fewer within the low 4 bytes of a
 * 16-byte line are virtualized, made to the virtual-APIC page, at offset
 * 080H, with "virtual-interrupt delivery" at 0B0H and 300H, with "IPI
 * virtualization" writes at 300H, and with "APIC-register virtualization"
 * in the lines it lists; others exit, before they are made, as do all of
 * event delivery's, though the processor virtualizes some of those.
 */
static bool vmx_apic_virtualized(CPUX86State *env, hwaddr offset,
                                 unsigned size, bool write)
{
    uint32_t proc2 = vmx_proc2(env);
    uint64_t lines = write ? VMX_APIC_REG_VIRT_WRITES : VMX_APIC_REG_VIRT_READS;

    if (!(VMCS(PROC_CONTROLS) & VMX_CPU_BASED_TPR_SHADOW) || size > 4 ||
        ((offset | (offset + size - 1)) & 0xc) ||
        (env->vmx.idt_vectoring_info & VMX_INTR_VALID)) {
        return false;
    }
    return offset == 0x80 ||
           ((proc2 & VMX_SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY) &&
            (offset == VMX_VAPIC_VEOI || offset == VMX_VAPIC_VICR_LO)) ||
           (write && (vmx_proc3(env) & VMX_TERTIARY_EXEC_IPI_VIRT) &&
            offset == VMX_VAPIC_VICR_LO) ||
           ((proc2 & VMX_SECONDARY_EXEC_APIC_REGISTER_VIRT) &&
            offset < 0x400 && (lines & VMX_APIC_LINE(offset)));
}

static G_NORETURN void vmx_apic_access_exit(CPUX86State *env, hwaddr offset,
                                            uint32_t type, uintptr_t ra)
{
    if (env->vmx.idt_vectoring_info & VMX_INTR_VALID) {
        type = VMX_APIC_ACCESS_DELIVERY;
    }
    x86_vmx_exit(env, VMX_EXIT_APIC_ACCESS, (offset & 0xfff) | type << 12, ra);
}

G_NORETURN void x86_vmx_apic_fetch_exit(CPUX86State *env, vaddr addr,
                                        uintptr_t ra)
{
    vmx_apic_access_exit(env, addr, VMX_APIC_ACCESS_FETCH, ra);
}

uint64_t x86_vmx_apic_read(CPUX86State *env, hwaddr offset, unsigned size,
                           uintptr_t ra)
{
    uint8_t buf[8];

    if (!vmx_apic_virtualized(env, offset, size, false)) {
        vmx_apic_access_exit(env, offset, VMX_APIC_ACCESS_READ, ra);
    }
    address_space_read(env_cpu(env)->as, VMCS(VIRTUAL_APIC_ADDR) + offset,
                       MEMTXATTRS_UNSPECIFIED, buf, size);
    return ldn_le_p(buf, size);
}

/*
 * A virtualized write and its APIC-write emulation (Intel SDM 325462-093
 * Vol. 3C, 32.4.3.2): at offset 080H, bytes 3:1 of VTPR clear, then TPR
 * virtualization; with virtual-interrupt delivery, at 0B0H, VEOI clears,
 * then EOI virtualization, and at 300H, a fixed edge-triggered self-IPI of
 * vector 10H or above in VICR_LO, its reserved bits and delivery status
 * clear, is virtualized; otherwise there, with IPI virtualization, a fixed
 * edge-triggered IPI to a physical destination, no shorthand, reserved
 * bits and delivery status clear, to the APIC ID in VICR_HI[31:24]; at
 * 310H to 313H, bytes 2:0 of VICR_HI clear; at others, an APIC-write VM
 * exit, trap-like. It comes at once, not after the operation, so a
 * trap-like exit leaves out what the instruction does past its store.
 */
void x86_vmx_apic_write(CPUX86State *env, hwaddr offset, uint64_t val,
                        unsigned size, uintptr_t ra)
{
    CPUState *cs = env_cpu(env);
    hwaddr vapic = VMCS(VIRTUAL_APIC_ADDR);
    bool vid = vmx_proc2(env) & VMX_SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY;
    bool ipiv = vmx_proc3(env) & VMX_TERTIARY_EXEC_IPI_VIRT;
    uint32_t icr;
    uint8_t buf[8];

    if (!vmx_apic_virtualized(env, offset, size, true)) {
        vmx_apic_access_exit(env, offset, VMX_APIC_ACCESS_WRITE, ra);
    }
    stn_le_p(buf, size, val);
    address_space_write(cs->as, vapic + offset, MEMTXATTRS_UNSPECIFIED, buf,
                        size);
    icr = x86_ldl_phys(cs, vapic + VMX_VAPIC_VICR_LO);
    if (offset == 0x80) {
        x86_stl_phys(cs, vapic + 0x80, x86_ldub_phys(cs, vapic + 0x80));
        vmx_tpr_virtualize(env, ra);
    } else if (vid && offset == VMX_VAPIC_VEOI) {
        x86_stl_phys(cs, vapic + VMX_VAPIC_VEOI, 0);
        vmx_eoi_virtualize(env, ra);
    } else if (vid && offset == VMX_VAPIC_VICR_LO &&
               (icr & 0xffffb700) == 1 << 18 && (icr & 0xf0)) {
        vmx_self_ipi_virtualize(env, icr & 0xff);
    } else if (ipiv && offset == VMX_VAPIC_VICR_LO &&
               !(icr & 0xffffbf00)) {
        vmx_ipi_virtualize(env, icr & 0xff,
                           x86_ldl_phys(cs, vapic + 0x310) >> 24, ra);
    } else if (offset >= 0x310 && offset <= 0x313) {
        x86_stl_phys(cs, vapic + 0x310,
                     x86_ldl_phys(cs, vapic + 0x310) & 0xff000000);
    } else {
        vmx_trap_exit(env, VMX_EXIT_APIC_WRITE, offset, ra);
    }
}

/*
 * RDMSR and WRMSR of 800H to 8FFH under "virtualize x2APIC mode", whatever
 * the local APIC's mode (Intel SDM 325462-093 Vol. 3C, 32.5): reads of
 * 808H, and with "APIC-register virtualization" of all of them, give the
 * 8 bytes at (ECX & FFH) << 4 on the virtual-APIC page; writes of 808H,
 * with virtual-interrupt delivery of 80BH and 83FH, and with IPI
 * virtualization of 830H, store EDX:EAX there after the usual checks of
 * reserved bits, then virtualize the TPR, an EOI, a self-IPI of vector 10H
 * or above, else exit as an APIC write of 3F0H would, or a fixed
 * edge-triggered IPI to the physical destination EDX, no shorthand, else
 * exit as an APIC write of 300H would. Both are false where the access
 * goes on as usual.
 */
static bool vmx_x2apic_virtualized(CPUX86State *env, uint32_t msr)
{
    return env->vmx.nonroot && msr >= MSR_APIC_START && msr <= MSR_APIC_END &&
           (vmx_proc2(env) & VMX_SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE);
}

bool x86_vmx_x2apic_rdmsr(CPUX86State *env, uint32_t msr, uint64_t *val)
{
    if (!vmx_x2apic_virtualized(env, msr) ||
        (msr != 0x808 &&
         !(vmx_proc2(env) & VMX_SECONDARY_EXEC_APIC_REGISTER_VIRT))) {
        return false;
    }
    *val = x86_ldq_phys(env_cpu(env),
                        VMCS(VIRTUAL_APIC_ADDR) + ((msr & 0xff) << 4));
    return true;
}

bool x86_vmx_x2apic_wrmsr(CPUX86State *env, uint32_t msr, uint64_t val,
                          uintptr_t ra)
{
    bool vid = vmx_proc2(env) & VMX_SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY;
    bool ipiv = vmx_proc3(env) & VMX_TERTIARY_EXEC_IPI_VIRT;

    if (!vmx_x2apic_virtualized(env, msr) ||
        !(msr == 0x808 || (vid && (msr == 0x80b || msr == 0x83f)) ||
          (ipiv && msr == 0x830))) {
        return false;
    }
    if (msr == 0x830 ? (val & 0xfff32000) :
        msr == 0x80b ? val != 0 : val >> 8 != 0) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }
    x86_stq_phys(env_cpu(env), VMCS(VIRTUAL_APIC_ADDR) + ((msr & 0xff) << 4),
                 val);
    if (msr == 0x808) {
        vmx_tpr_virtualize(env, ra);
    } else if (msr == 0x80b) {
        vmx_eoi_virtualize(env, ra);
    } else if (msr == 0x830) {
        if (val & 0xc9f00) {
            vmx_trap_exit(env, VMX_EXIT_APIC_WRITE, VMX_VAPIC_VICR_LO, ra);
        }
        vmx_ipi_virtualize(env, val & 0xff, val >> 32, ra);
    } else if (val & 0xf0) {
        vmx_self_ipi_virtualize(env, val);
    } else {
        vmx_trap_exit(env, VMX_EXIT_APIC_WRITE, 0x3f0, ra);
    }
    return true;
}

/* CLTS exits where the masks own CR0.TS and the shadow has it set. */
bool x86_vmx_clts(CPUX86State *env, uintptr_t ra)
{
    uint64_t mask = VMCS(CR0_MASK);

    if (!(mask & CR0_TS_MASK)) {
        return true;
    }
    if (VMCS(CR0_SHADOW) & CR0_TS_MASK) {
        x86_vmx_exit(env, VMX_EXIT_CR_ACCESS, 2 << 4, ra);
    }
    return false;
}

/*
 * LMSW exits where an owned bit of MP, EM, and TS would change from its
 * shadow, or PE be set over a shadow PE of 0; otherwise it writes the bits
 * the masks leave the guest.
 */
uint32_t x86_vmx_lmsw(CPUX86State *env, uint32_t src, bool mem,
                      uintptr_t ra)
{
    uint64_t mask = VMCS(CR0_MASK) & 0xf;
    uint64_t shadow = VMCS(CR0_SHADOW);
    uint32_t cr0 = (env->cr[0] & ~0xe) | (src & 0xf);

    if (((src ^ shadow) & mask & 0xe) ||
        ((mask & CR0_PE_MASK) && !(shadow & CR0_PE_MASK) &&
         (src & CR0_PE_MASK))) {
        x86_vmx_exit(env, VMX_EXIT_CR_ACCESS,
                     3 << 4 | (mem ? 1 << 6 : 0) | (uint64_t)src << 16, ra);
    }
    return (cr0 & ~mask) | (env->cr[0] & mask);
}

/*
 * PAUSE-loop exiting at CPL 0 (Intel SDM 325462-093 Vol. 3C, 28.1.3): a
 * PAUSE more than PLE_Gap TSC ticks after the last one starts a loop, as
 * the first after the VM entry does, and one more than PLE_Window ticks
 * into a loop exits.
 */
static bool vmx_pause_loop(CPUX86State *env)
{
    uint64_t now = cpu_get_tsc(env);

    if (!env->vmx.ple_loop || now - env->vmx.ple_last > VMCS(PLE_GAP)) {
        env->vmx.ple_loop = true;
        env->vmx.ple_first = now;
    }
    env->vmx.ple_last = now;
    return now - env->vmx.ple_first > VMCS(PLE_WINDOW);
}

/*
 * What QEMU's SVM intercept checks ask for, in VMX terms (Intel SDM
 * 325462-093 Vol. 3C, 28.1 and 28.2): param is the MSR access's direction,
 * INVLPG's address, a CR or DR access's GPR, or an exception's error code.
 */
void x86_vmx_check_intercept(CPUX86State *env, uint32_t type,
                             uint64_t param, uintptr_t ra)
{
    uint32_t proc = VMCS(PROC_CONTROLS);
    uint32_t proc2 = vmx_proc2(env);
    uint64_t gpr = param & 0xf;

    switch (type) {
    case SVM_EXIT_CPUID:
        x86_vmx_exit(env, VMX_EXIT_CPUID, 0, ra);
    case SVM_EXIT_INVD:
        x86_vmx_exit(env, VMX_EXIT_INVD, 0, ra);
    case SVM_EXIT_XSETBV:
        x86_vmx_exit(env, VMX_EXIT_XSETBV, 0, ra);
    case SVM_EXIT_HLT:
        if (proc & VMX_CPU_BASED_HLT_EXITING) {
            x86_vmx_exit(env, VMX_EXIT_HLT, 0, ra);
        }
        break;
    case SVM_EXIT_INVLPG:
        if (proc & VMX_CPU_BASED_INVLPG_EXITING) {
            x86_vmx_exit(env, VMX_EXIT_INVLPG, param, ra);
        }
        break;
    case SVM_EXIT_RDPMC:
        if (proc & VMX_CPU_BASED_RDPMC_EXITING) {
            x86_vmx_exit(env, VMX_EXIT_RDPMC, 0, ra);
        }
        break;
    case SVM_EXIT_RDTSC:
        if (proc & VMX_CPU_BASED_RDTSC_EXITING) {
            x86_vmx_exit(env, VMX_EXIT_RDTSC, 0, ra);
        }
        break;
    case SVM_EXIT_RDTSCP:
        if (proc & VMX_CPU_BASED_RDTSC_EXITING) {
            x86_vmx_exit(env, VMX_EXIT_RDTSCP, 0, ra);
        }
        break;
    case SVM_EXIT_MONITOR:
        if (proc & VMX_CPU_BASED_MONITOR_EXITING) {
            x86_vmx_exit(env, VMX_EXIT_MONITOR, 0, ra);
        }
        break;
    case SVM_EXIT_MWAIT:
        /*
         * The qualification tells whether address-range monitoring was
         * armed (Intel SDM 325462-093 Vol. 3C, 30.2.1).
         */
        if (proc & VMX_CPU_BASED_MWAIT_EXITING) {
            x86_vmx_exit(env, VMX_EXIT_MWAIT, env->monitor_armed, ra);
        }
        break;
    case SVM_EXIT_PAUSE:
        if ((proc & VMX_CPU_BASED_PAUSE_EXITING) ||
            ((proc2 & VMX_SECONDARY_EXEC_PAUSE_LOOP_EXITING) &&
             !(env->hflags & HF_CPL_MASK) && vmx_pause_loop(env))) {
            x86_vmx_exit(env, VMX_EXIT_PAUSE, 0, ra);
        }
        break;
    case SVM_EXIT_WBINVD:
        if (proc2 & VMX_SECONDARY_EXEC_WBINVD_EXITING) {
            x86_vmx_exit(env, VMX_EXIT_WBINVD, 0, ra);
        }
        break;
    case SVM_EXIT_IDTR_READ:
    case SVM_EXIT_GDTR_READ:
    case SVM_EXIT_IDTR_WRITE:
    case SVM_EXIT_GDTR_WRITE:
        if (proc2 & VMX_SECONDARY_EXEC_DESC) {
            x86_vmx_exit(env, VMX_EXIT_GDTR_IDTR, 0, ra);
        }
        break;
    case SVM_EXIT_LDTR_READ:
    case SVM_EXIT_TR_READ:
    case SVM_EXIT_LDTR_WRITE:
    case SVM_EXIT_TR_WRITE:
        if (proc2 & VMX_SECONDARY_EXEC_DESC) {
            x86_vmx_exit(env, VMX_EXIT_LDTR_TR, 0, ra);
        }
        break;
    case SVM_EXIT_READ_CR0 + 3:
        if (proc & VMX_CPU_BASED_CR3_STORE_EXITING) {
            x86_vmx_exit(env, VMX_EXIT_CR_ACCESS, 3 | 1 << 4 | gpr << 8, ra);
        }
        break;
    case SVM_EXIT_READ_CR0 + 8:
        if (proc & VMX_CPU_BASED_CR8_STORE_EXITING) {
            x86_vmx_exit(env, VMX_EXIT_CR_ACCESS, 8 | 1 << 4 | gpr << 8, ra);
        }
        break;
    case SVM_EXIT_READ_DR0 ... SVM_EXIT_READ_DR0 + 7:
    case SVM_EXIT_WRITE_DR0 ... SVM_EXIT_WRITE_DR0 + 7:
        if (proc & VMX_CPU_BASED_MOV_DR_EXITING) {
            bool read = type < SVM_EXIT_WRITE_DR0;
            int dr = type - (read ? SVM_EXIT_READ_DR0 : SVM_EXIT_WRITE_DR0);

            x86_vmx_exit(env, VMX_EXIT_DR_ACCESS,
                         dr | (read ? 1 << 4 : 0) | gpr << 8, ra);
        }
        break;
    case SVM_EXIT_MSR:
        if (vmx_msr_exits(env, env->regs[R_ECX], param)) {
            x86_vmx_exit(env, param ? VMX_EXIT_WRMSR : VMX_EXIT_RDMSR, 0, ra);
        }
        break;
    case SVM_EXIT_EXCP_BASE ... SVM_EXIT_EXCP_BASE + 31:
        vmx_exception_exit(env, type - SVM_EXIT_EXCP_BASE, param, ra);
        break;
    case SVM_EXIT_INIT:
        cpu_reset_interrupt(env_cpu(env), CPU_INTERRUPT_INIT);
        env->vmx.exit_hlt = env->vmx.hlt_wake;
        env->vmx.hlt_wake = false;
        x86_vmx_exit(env, VMX_EXIT_INIT, 0, ra);
    case SVM_EXIT_SHUTDOWN:
        x86_vmx_exit(env, VMX_EXIT_TRIPLE_FAULT, 0, ra);
    default:
        break;
    }
}

/*
 * The VMX instructions exit unconditionally in non-root operation, but
 * VMREAD and VMWRITE where "VMCS shadowing" lets them access the shadow
 * VMCS: for a field encoding, in the register that bits 31:28 of the
 * instruction information name, with bits 63:15 clear and its bit in the
 * VMREAD or VMWRITE bitmap clear (Intel SDM 325462-093 Vol. 3C, 28.1.3).
 * The instruction information and displacement come from the translator.
 */
static bool vmx_shadowed(CPUX86State *env, uint32_t reason,
                         uint32_t insn_info)
{
    uint64_t field = env->regs[insn_info >> 28];
    uint64_t bitmap;

    if (!(env->hflags & HF_CS64_MASK)) {
        field = (uint32_t)field;
    }
    if ((reason != VMX_EXIT_VMREAD && reason != VMX_EXIT_VMWRITE) ||
        !(vmx_proc2(env) & VMX_SECONDARY_EXEC_SHADOW_VMCS) || field >> 15) {
        return false;
    }
    bitmap = reason == VMX_EXIT_VMREAD ? VMCS(VMREAD_BITMAP) :
                                         VMCS(VMWRITE_BITMAP);
    return !(x86_ldub_phys(env_cpu(env), bitmap + (field >> 3)) &
             1 << (field & 7));
}

void HELPER(vmx_insn_exit)(CPUX86State *env, uint32_t reason,
                           uint32_t insn_info, target_ulong disp)
{
    if (env->vmx.nonroot && !vmx_shadowed(env, reason, insn_info)) {
        VMCS_SET(EXIT_INSN_INFO, insn_info);
        x86_vmx_exit(env, reason, disp, GETPC());
    }
}

/*
 * A task switch exits before it changes anything: the qualification has
 * the new TSS's selector and the source, 0 CALL, 1 IRET, 2 JMP, or 3 a
 * task gate in the IDT (Intel SDM 325462-093 Vol. 3C, Table 30-2).
 */
void x86_vmx_task_switch(CPUX86State *env, int selector, int source,
                         uintptr_t ra)
{
    x86_vmx_exit(env, VMX_EXIT_TASK_SWITCH,
                 (selector & 0xffff) | (uint64_t)source << 30, ra);
}

/*
 * Event delivery in non-root operation: what IDT-vectoring information an
 * exit during it reports (Intel SDM 325462-093 Vol. 3C, 30.2.4).
 */
void x86_vmx_event_start(CPUX86State *env, int intno, int is_int,
                         int error_code, int is_hw, int rm)
{
    uint32_t type;

    if (is_hw) {
        type = intno == EXCP02_NMI ? VMX_INTR_TYPE_NMI
                                   : VMX_INTR_TYPE_EXT_INTR;
    } else if (env->vmx.soft_exception) {
        type = env->vmx.soft_exception;
    } else if (is_int) {
        type = VMX_INTR_TYPE_SW_INTR;
    } else {
        type = VMX_INTR_TYPE_HW_EXCEPTION;
    }
    env->vmx.soft_exception = 0;
    env->vmx.idt_vectoring_info = intno | type << VMX_INTR_TYPE_SHIFT |
                                  VMX_INTR_VALID;
    env->vmx.idt_vectoring_error = 0;
    if (type == VMX_INTR_TYPE_HW_EXCEPTION && !rm &&
        exception_has_error_code(intno)) {
        env->vmx.idt_vectoring_info |= VMX_INTR_ERROR_VALID;
        env->vmx.idt_vectoring_error = error_code;
    }
}

/*
 * Under the monitor trap flag, an MTF VM exit comes once an event is
 * delivered, before its handler's first instruction (Intel SDM 325462-093
 * Vol. 3C, 28.5.2).
 */
void x86_vmx_event_end(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);

    env->vmx.idt_vectoring_info = 0;
    if (env->vmx.mtf) {
        env->vmx.mtf_pending = true;
        cpu_set_interrupt(cs, CPU_INTERRUPT_VMX);
        qatomic_set(&cs->neg.icount_decr.u16.high, -1);
    }
}

/*
 * The MTF VM exit after an instruction, ahead of the debug traps it
 * raised, which stay pending: those of single-stepping and I/O
 * breakpoints, in traps, and of data breakpoints, with the enabled-
 * breakpoint bit where DR7 enables one of them (Intel SDM 325462-093
 * Vol. 3C, 28.5.2 and 30.3.4).
 */
G_NORETURN void x86_vmx_mtf_step(CPUX86State *env, uint32_t traps)
{
    bool enabled;
    uint32_t pending = traps | hw_data_breakpoint_hits(env, &enabled);

    if (enabled || (traps & 0xf)) {
        pending |= VMX_PENDING_DBG_ENABLED_BP;
    }
    env->vmx.mtf_pending = false;
    env->vmx.exit_pending_dbg = pending;
    x86_vmx_exit(env, VMX_EXIT_MONITOR_TRAP_FLAG, 0, 0);
}

/*
 * The PDPTEs of a guest with PAE paging under EPT, which an exit saves
 * (Intel SDM 325462-093 Vol. 3C, 30.3.4): the registers the entry loaded,
 * else the guest's own, at CR3 through EPT.
 */
static void vmx_save_pdptes(CPUX86State *env)
{
    for (int i = 0; i < 4; i++) {
        uint64_t pdpte = 0;
        hwaddr hpa;
        int prot, size;

        if (env->vmx.pdpte_loaded) {
            pdpte = env->vmx.pdpte[i];
        } else if (x86_vmx_ept_translate(env, (env->cr[3] & ~0x1fULL) + 8 * i,
                                         MMU_DATA_LOAD, false, &hpa, &prot,
                                         &size)) {
            pdpte = x86_ldq_phys(env_cpu(env), hpa);
        }
        x86_vmcs_write(env, VMCS_GUEST_PDPTE(i), pdpte);
    }
}

/*
 * The VMX-preemption timer counts down by one each time bit
 * VMX_MISC_TIMER_RATE of the TSC changes, from the value VM entry loaded
 * (Intel SDM 325462-093 Vol. 3C, 28.5.1 and 29.7.4).
 */
static uint64_t vmx_timer_tsc(CPUX86State *env)
{
    return (cpu_get_tsc(env) + env->tsc_written_delta) >> VMX_MISC_TIMER_RATE;
}

static uint32_t vmx_timer_left(CPUX86State *env)
{
    uint64_t gone = vmx_timer_tsc(env) - env->vmx.timer_start;

    return gone >= env->vmx.timer_value ? 0 : env->vmx.timer_value - gone;
}

static bool vmx_timer_expired(const CPUX86State *env)
{
    return env->vmx.timer_on && !vmx_timer_left((CPUX86State *)env);
}

/*
 * Software read the TSC: past the VMX-preemption timer's deadline, the
 * timer's VM exit comes before the next instruction (Intel SDM 325462-093
 * Vol. 3C, 28.5.1 and 28.2), not when its QEMU timer gets to run. The
 * instructions that read the TSC end their TB in guest mode.
 */
void x86_vmx_tsc_seen(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);

    if (env->vmx.nonroot && vmx_timer_expired(env)) {
        cpu_set_interrupt(cs, CPU_INTERRUPT_VMX);
        qatomic_set(&cs->neg.icount_decr.u16.high, -1);
    }
}

static void vmx_timer_arm(CPUX86State *env)
{
    uint64_t ticks = (uint64_t)vmx_timer_left(env) << VMX_MISC_TIMER_RATE;

    timer_mod(env_archcpu(env)->vmx_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
              cpu_tsc_ticks_ns(env, ticks));
}

/* An expiry has the processor look at it; early calls arm again. */
static void vmx_timer_cb(void *opaque)
{
    X86CPU *cpu = opaque;
    CPUX86State *env = &cpu->env;

    if (!env->vmx.timer_on) {
        return;
    }
    if (vmx_timer_left(env)) {
        vmx_timer_arm(env);
        return;
    }
    cpu_interrupt(CPU(cpu), CPU_INTERRUPT_VMX);
}

void x86_vmx_init(X86CPU *cpu)
{
    cpu->vmx_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, vmx_timer_cb, cpu);
}

static void vmx_timer_start(CPUX86State *env)
{
    env->vmx.timer_on = true;
    env->vmx.timer_value = VMCS(PREEMPTION_TIMER);
    env->vmx.timer_start = vmx_timer_tsc(env);
    /* One that expires during VM entry exits before any instruction. */
    if (env->vmx.timer_value) {
        vmx_timer_arm(env);
    } else {
        cpu_set_interrupt(env_cpu(env), CPU_INTERRUPT_VMX);
    }
}

/* The guest state a VM exit saves (Intel SDM 325462-093 Vol. 3C, 30.3). */
static void vmx_save_guest(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);
    uint32_t exit_ctl = VMCS(EXIT_CONTROLS);
    uint32_t intr = 0;

    VMCS_SET(GUEST_CR0, env->cr[0]);
    VMCS_SET(GUEST_CR3, env->cr[3]);
    VMCS_SET(GUEST_CR4, env->cr[4]);
    if ((vmx_proc2(env) & VMX_SECONDARY_EXEC_ENABLE_EPT) &&
        (env->cr[0] & CR0_PG_MASK) && (env->cr[4] & CR4_PAE_MASK) &&
        !(env->efer & MSR_EFER_LMA)) {
        vmx_save_pdptes(env);
    }
    if (exit_ctl & VMX_VM_EXIT_SAVE_DEBUG_CONTROLS) {
        VMCS_SET(GUEST_DR7, env->dr[7]);
        VMCS_SET(GUEST_DEBUGCTL, env->debugctl);
    }
    VMCS_SET(GUEST_SYSENTER_CS, env->sysenter_cs);
    VMCS_SET(GUEST_SYSENTER_ESP, env->sysenter_esp);
    VMCS_SET(GUEST_SYSENTER_EIP, env->sysenter_eip);
    if (exit_ctl & VMX_VM_EXIT_SAVE_IA32_PAT) {
        VMCS_SET(GUEST_PAT, env->pat);
    }
    if (exit_ctl & VMX_VM_EXIT_SAVE_IA32_EFER) {
        VMCS_SET(GUEST_EFER, env->efer);
    }
    if (exit_ctl & VMX_VM_EXIT_SAVE_IA32_PERF_GLOBAL_CTRL) {
        VMCS_SET(GUEST_PERF_GLOBAL_CTRL, env->msr_global_ctrl);
    }
    for (int i = 0; i < 8; i++) {
        const SegmentCache *sc = i == R_LDTR ? &env->ldt :
                                 i == R_TR ? &env->tr : &env->segs[i];

        x86_vmcs_write(env, VMCS_GUEST_SEL(i), sc->selector);
        x86_vmcs_write(env, VMCS_GUEST_BASE(i), sc->base);
        x86_vmcs_write(env, VMCS_GUEST_LIMIT(i), sc->limit);
        x86_vmcs_write(env, VMCS_GUEST_AR(i), vmx_ar(sc));
    }
    VMCS_SET(GUEST_GDTR_BASE, env->gdt.base);
    VMCS_SET(GUEST_GDTR_LIMIT, env->gdt.limit);
    VMCS_SET(GUEST_IDTR_BASE, env->idt.base);
    VMCS_SET(GUEST_IDTR_LIMIT, env->idt.limit);
    VMCS_SET(GUEST_RIP, env->eip);
    VMCS_SET(GUEST_RSP, env->regs[R_ESP]);
    VMCS_SET(GUEST_RFLAGS, cpu_compute_eflags(env));
    if (env->hflags & HF_INHIBIT_IRQ_MASK) {
        intr |= env->shadow_movss ? VMX_BLOCKING_MOV_SS : VMX_BLOCKING_STI;
    }
    if (VMCS(PIN_CONTROLS) & VMX_PIN_BASED_VIRTUAL_NMIS ?
        env->vmx.vnmi_blocked : env->hflags2 & HF2_NMI_MASK) {
        intr |= VMX_BLOCKING_NMI;
    }
    VMCS_SET(GUEST_INTERRUPTIBILITY, intr);
    if (env->vmx.inactive) {
        VMCS_SET(GUEST_ACTIVITY, env->vmx.inactive);
    } else {
        VMCS_SET(GUEST_ACTIVITY, cs->halted || env->vmx.exit_hlt ?
                                 VMX_ACTIVITY_HLT : VMX_ACTIVITY_ACTIVE);
    }
    env->vmx.exit_hlt = false;
    if (env->vmx.timer_on &&
        (exit_ctl & VMX_VM_EXIT_SAVE_VMX_PREEMPTION_TIMER)) {
        VMCS_SET(PREEMPTION_TIMER, vmx_timer_left(env));
    }
    VMCS_SET(GUEST_PENDING_DBG, env->vmx.exit_pending_dbg);
    env->vmx.exit_pending_dbg = 0;
    env->vmx.db_held = 0;
    env->vmx.tlb_cr0 = env->cr[0];
    env->vmx.tlb_cr3 = env->cr[3];
    env->vmx.tlb_cr4 = env->cr[4];
    env->vmx.tlb_efer = env->efer;
    /* IA32_VMX_MISC bit 5: exits store EFER.LMA as "IA-32e mode guest". */
    VMCS_SET(ENTRY_CONTROLS, (VMCS(ENTRY_CONTROLS) & ~VMX_VM_ENTRY_IA32E_MODE) |
                             (env->efer & MSR_EFER_LMA ?
                              VMX_VM_ENTRY_IA32E_MODE : 0));
}

/*
 * A VMX abort: the indicator in the VMCS region, then shutdown
 * (Intel SDM 325462-093 Vol. 3C, 30.7).
 */
static G_NORETURN void vmx_abort(CPUX86State *env, uint32_t indicator)
{
    CPUState *cs = env_cpu(env);

    x86_stl_phys(cs, env->vmx.vmcs_ptr + 4, indicator);
    qemu_log_mask(LOG_GUEST_ERROR, "VMX abort %u\n", indicator);
    qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
    /* Else the main loop delivers the VM exit, still pending, again. */
    cs->exception_index = EXCP_HLT;
    cpu_loop_exit(cs);
}

/*
 * The MSR areas of VM entries and exits (Intel SDM 325462-093 Vol. 3C,
 * 27.7.2, 27.8.2, 29.4, 30.4, 30.6): 16-byte entries of an MSR index,
 * reserved bits, and the value. Loading stops at the first entry the
 * processor refuses, whose number from 1 is returned, 0 for none.
 */
static uint32_t vmx_msr_area_load(CPUX86State *env, uint64_t addr,
                                  uint32_t count)
{
    CPUState *cs = env_cpu(env);

    for (uint32_t i = 0; i < count; i++) {
        uint32_t msr = x86_ldl_phys(cs, addr + 16 * i);
        uint32_t reserved = x86_ldl_phys(cs, addr + 16 * i + 4);
        uint64_t val = x86_ldq_phys(cs, addr + 16 * i + 8);

        if (reserved || msr == MSR_FSBASE || msr == MSR_GSBASE ||
            msr == MSR_IA32_UCODE_REV || (msr >> 8) == 8 ||
            !x86_cpu_wrmsr(env, msr, val)) {
            return i + 1;
        }
    }
    return 0;
}

static bool vmx_msr_area_store(CPUX86State *env, uint64_t addr,
                               uint32_t count)
{
    CPUState *cs = env_cpu(env);

    for (uint32_t i = 0; i < count; i++) {
        uint32_t msr = x86_ldl_phys(cs, addr + 16 * i);
        uint64_t val;

        /*
         * IA32_SMBASE reads only in SMM, where no exit ends
         * (Intel SDM 325462-093 Vol. 3C, 30.4).
         */
        if (x86_ldl_phys(cs, addr + 16 * i + 4) || (msr >> 8) == 8 ||
            msr == MSR_IA32_SMBASE) {
            return false;
        }
        /* The TSC offset applies to the guest's reads, not the store. */
        if (msr == MSR_IA32_TSC) {
            val = cpu_get_tsc(env) + env->tsc_written_delta;
        } else if (!x86_cpu_rdmsr(env, msr, &val)) {
            return false;
        }
        x86_stq_phys(cs, addr + 16 * i + 8, val);
    }
    return true;
}

/*
 * The host state a VM exit loads (Intel SDM 325462-093 Vol. 3C, 30.5),
 * also after a VM-entry failure.
 */
static void vmx_load_host(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);
    uint32_t exit_ctl = VMCS(EXIT_CONTROLS);
    bool host64 = exit_ctl & VMX_VM_EXIT_HOST_ADDR_SPACE_SIZE;
    const uint64_t cr0_kept = CR0_ET_MASK | CR0_CD_MASK | CR0_NW_MASK |
                              ~0xffffffffULL | 0x1ff80000 | 0x20000 | 0xffc0;
    uint64_t cr0 = (VMCS(HOST_CR0) & ~cr0_kept) | (env->cr[0] & cr0_kept);
    uint64_t cr4 = VMCS(HOST_CR4) | vmx_cr_fixed0(4);
    uint64_t efer;
    uint32_t data = DESC_P_MASK | DESC_S_MASK | DESC_W_MASK | DESC_A_MASK |
                    DESC_B_MASK | DESC_G_MASK;

    cr0 |= vmx_cr_fixed0(0);
    if (host64) {
        cr4 |= CR4_PAE_MASK;
    } else {
        cr4 &= ~(CR4_PCIDE_MASK | CR4_FRED_MASK);
    }
    if (exit_ctl & VMX_VM_EXIT_LOAD_IA32_EFER) {
        efer = VMCS(HOST_EFER);
    } else {
        efer = env->efer & ~(MSR_EFER_LMA | MSR_EFER_LME);
        if (host64) {
            efer |= MSR_EFER_LMA | MSR_EFER_LME;
        }
    }

    env->hflags &= ~(HF_GUEST_MASK | HF_INHIBIT_IRQ_MASK);
    env->vmx.nonroot = false;
    env->vmx.mtf = false;
    env->vmx.mtf_pending = false;
    env->vmx.apic_access = ~0ULL;
    env->vmx.tpr_exit_pending = false;
    env->vmx.vintr_pending = false;
    env->vmx.inactive = 0;
    env->vmx.timer_on = false;
    timer_del(env_archcpu(env)->vmx_timer);
    env->monitor_armed = false;
    env->umonitor_armed = false;
    cpu_reset_interrupt(cs, CPU_INTERRUPT_VMX);
    cs->halted = 0;

    env->svm_loading_crs = true;
    cpu_x86_update_cr0(env, cr0);
    cpu_x86_update_cr4(env, cr4);
    cpu_x86_update_cr3(env, VMCS(HOST_CR3));
    env->svm_loading_crs = false;
    cpu_load_efer(env, efer);
    /*
     * A data breakpoint's #DB still to come is the guest's, which the exit
     * saved or dropped; its watchpoint goes with the guest's DR7.
     */
    if (cs->watchpoint_hit && (cs->watchpoint_hit->flags & BP_CPU)) {
        cs->watchpoint_hit = NULL;
        cpu_reset_interrupt(cs, CPU_INTERRUPT_DEBUG);
    }
    cpu_x86_update_dr7(env, 0x400);
    env->debugctl = 0;
    env->sysenter_cs = (uint32_t)VMCS(HOST_SYSENTER_CS);
    env->sysenter_esp = VMCS(HOST_SYSENTER_ESP);
    env->sysenter_eip = VMCS(HOST_SYSENTER_EIP);
    if (exit_ctl & VMX_VM_EXIT_LOAD_IA32_PAT) {
        env->pat = VMCS(HOST_PAT);
    }
    if (exit_ctl & VMX_VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL) {
        x86_pmu_set_global_ctrl(env, VMCS(HOST_PERF_GLOBAL_CTRL));
    }

    cpu_x86_load_seg_cache(env, R_CS, VMCS(HOST_SEL(R_CS)), 0, 0xffffffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_CS_MASK |
                           DESC_R_MASK | DESC_A_MASK | DESC_G_MASK |
                           (host64 ? DESC_L_MASK : DESC_B_MASK));
    for (int i = R_ES; i <= R_GS; i++) {
        uint32_t sel = x86_vmcs_read(env, VMCS_HOST_SEL(i));
        target_ulong base = 0;

        if (i == R_CS) {
            continue;
        }
        if (i == R_FS) {
            base = VMCS(HOST_FS_BASE);
        } else if (i == R_GS) {
            base = VMCS(HOST_GS_BASE);
        }
        cpu_x86_load_seg_cache(env, i, sel, base, sel ? 0xffffffff : 0,
                               sel || i == R_SS ? data : 0);
    }
    cpu_x86_load_seg_cache(env, R_TR, VMCS(HOST_TR_SEL), VMCS(HOST_TR_BASE),
                           0x67, DESC_P_MASK | 11 << DESC_TYPE_SHIFT);
    cpu_x86_load_seg_cache(env, R_LDTR, 0, 0, 0, 0);
    env->gdt.base = VMCS(HOST_GDTR_BASE);
    env->gdt.limit = 0xffff;
    env->idt.base = VMCS(HOST_IDTR_BASE);
    env->idt.limit = 0xffff;

    env->eip = VMCS(HOST_RIP);
    env->regs[R_ESP] = VMCS(HOST_RSP);
    env->eflags = 0;
    cpu_load_eflags(env, 2, ~(CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C |
                              DF_MASK));
    env->cc_op = CC_OP_EFLAGS;
    if (env->vmx.exit_nmi) {
        env->hflags2 |= HF2_NMI_MASK;
        env->vmx.exit_nmi = false;
    }
    env->hflags2 &= ~HF2_NPT_MASK;
    /*
     * Without VPIDs, exits drop the translations of VPID 0
     * (Intel SDM 325462-093 Vol. 3C, 30.5.5).
     */
    if (!(vmx_proc2(env) & VMX_SECONDARY_EXEC_ENABLE_VPID)) {
        tlb_flush(cs);
    }
}

/* The rest of a VM exit, from the main loop. */
void x86_vmx_do_vmexit(CPUX86State *env)
{
    VMCS_SET(IDT_VECTORING_INFO, env->vmx.idt_vectoring_info);
    VMCS_SET(IDT_VECTORING_ERROR, env->vmx.idt_vectoring_error);
    env->vmx.idt_vectoring_info = 0;
    VMCS_SET(ENTRY_INTR_INFO, VMCS(ENTRY_INTR_INFO) & ~VMX_INTR_VALID);
    vmx_save_guest(env);
    if (!vmx_msr_area_store(env, VMCS(EXIT_MSR_STORE_ADDR),
                            VMCS(EXIT_MSR_STORE_COUNT))) {
        vmx_abort(env, 1);
    }
    vmx_load_host(env);
    if (vmx_msr_area_load(env, VMCS(EXIT_MSR_LOAD_ADDR),
                          VMCS(EXIT_MSR_LOAD_COUNT))) {
        vmx_abort(env, 4);
    }
}

static bool vmx_eptp_valid(CPUX86State *env, uint64_t eptp);

/* The VMX control MSRs' settings a VM entry checks the controls against. */
static bool vmx_ctl_valid(CPUX86State *env, uint32_t index,
                          uint32_t true_index, uint32_t val)
{
    uint64_t msr;

    if (!(env->features[FEAT_VMX_BASIC] & MSR_VMX_BASIC_TRUE_CTLS) ||
        !true_index) {
        true_index = index;
    }
    if (!x86_vmx_read_msr(env, true_index, &msr)) {
        return !val;
    }
    return (val & (uint32_t)msr) == (uint32_t)msr && !(val & ~(msr >> 32));
}

static bool vmx_addr_valid(CPUX86State *env, uint64_t addr, uint64_t align)
{
    return !(addr & (align - 1)) && !(addr >> env_archcpu(env)->phys_bits);
}

/*
 * An MSR area, which with a nonzero count must be aligned and have its
 * first and last bytes within the address width (Intel SDM 325462-093 Vol.
 * 3C, 29.2.1.2 and 29.2.1.3). Past 512 times bits 27:25 of IA32_VMX_MISC
 * plus 1 entries the SDM leaves the outcome undefined (Intel SDM
 * 325462-093 Vol. 3D, A.6); the check refuses them, as Linux 7.3's KVM
 * does (nested_vmx_check_msr_switch()).
 */
static bool vmx_msr_area_valid(CPUX86State *env, uint64_t addr,
                               uint32_t count)
{
    uint32_t max = 512 * (((env->features[FEAT_VMX_MISC] &
                            MSR_VMX_MISC_MAX_MSR_LIST_SIZE_MASK) >> 25) + 1);

    return !count || (count <= max && vmx_addr_valid(env, addr, 16) &&
                      vmx_addr_valid(env, addr + 16ULL * count - 1, 1));
}

/*
 * The injected event's checks (Intel SDM 325462-093 Vol. 3C, 29.2.1.3):
 * a defined type, an NMI with vector 2, an exception with a vector below
 * 32, other events only as pending MTF VM exits, of vector 0, an error
 * code where the event has one, and an instruction length for software
 * events.
 */
static bool vmx_injection_valid(CPUX86State *env)
{
    uint32_t info = VMCS(ENTRY_INTR_INFO);
    uint32_t vector = info & VMX_INTR_VECTOR_MASK;
    uint32_t type = (info & VMX_INTR_TYPE_MASK) >> VMX_INTR_TYPE_SHIFT;
    bool real = (vmx_proc2(env) & VMX_SECONDARY_EXEC_UNRESTRICTED_GUEST) &&
                !(VMCS(GUEST_CR0) & CR0_PE_MASK);
    bool error = info & VMX_INTR_ERROR_VALID;
    uint32_t len = VMCS(ENTRY_INSN_LEN);

    if (!(info & VMX_INTR_VALID)) {
        return true;
    }
    if (type == 1 || (info & 0x7ffff000) ||
        (type == VMX_INTR_TYPE_NMI && vector != EXCP02_NMI) ||
        (type == VMX_INTR_TYPE_HW_EXCEPTION && vector > 31) ||
        (type == VMX_INTR_TYPE_OTHER &&
         (vector || !(env->features[FEAT_VMX_PROCBASED_CTLS] &
                      VMX_CPU_BASED_MONITOR_TRAP_FLAG)))) {
        return false;
    }
    if (error && (real || type != VMX_INTR_TYPE_HW_EXCEPTION)) {
        return false;
    }
    if (!(env->features[FEAT_VMX_BASIC] & MSR_VMX_BASIC_ANY_ERRCODE) &&
        error != (!real && type == VMX_INTR_TYPE_HW_EXCEPTION &&
                  exception_has_error_code(vector))) {
        return false;
    }
    if (error && (VMCS(ENTRY_EXCEPTION_ERROR) >> 16)) {
        return false;
    }
    if ((type == VMX_INTR_TYPE_SW_INTR ||
         type == VMX_INTR_TYPE_PRIV_SW_EXCEPTION ||
         type == VMX_INTR_TYPE_SW_EXCEPTION) &&
        (len > 15 || (!len && !(env->features[FEAT_VMX_MISC] &
                                MSR_VMX_MISC_ZERO_LEN_INJECT)))) {
        return false;
    }
    return true;
}

/*
 * The VM-execution, VM-exit, and VM-entry controls (Intel SDM 325462-093
 * Vol. 3C, 29.2.1).
 */
static bool vmx_controls_valid(CPUX86State *env)
{
    uint32_t pin = VMCS(PIN_CONTROLS);
    uint32_t proc = VMCS(PROC_CONTROLS);
    uint32_t proc2 = vmx_proc2(env);
    uint64_t proc3 = vmx_proc3(env);
    uint32_t exit_ctl = VMCS(EXIT_CONTROLS);
    uint32_t entry_ctl = VMCS(ENTRY_CONTROLS);

    if (proc3 & ~env->features[FEAT_VMX_TERTIARY_CTLS]) {
        return false;
    }
    if (!vmx_ctl_valid(env, MSR_IA32_VMX_PINBASED_CTLS,
                       MSR_IA32_VMX_TRUE_PINBASED_CTLS, pin) ||
        !vmx_ctl_valid(env, MSR_IA32_VMX_PROCBASED_CTLS,
                       MSR_IA32_VMX_TRUE_PROCBASED_CTLS, proc) ||
        !vmx_ctl_valid(env, MSR_IA32_VMX_PROCBASED_CTLS2, 0, proc2) ||
        !vmx_ctl_valid(env, MSR_IA32_VMX_EXIT_CTLS,
                       MSR_IA32_VMX_TRUE_EXIT_CTLS, exit_ctl) ||
        !vmx_ctl_valid(env, MSR_IA32_VMX_ENTRY_CTLS,
                       MSR_IA32_VMX_TRUE_ENTRY_CTLS, entry_ctl)) {
        return false;
    }
    if (VMCS(CR3_TARGET_COUNT) > VMX_MISC_CR3_TARGETS) {
        return false;
    }
    if ((proc & VMX_CPU_BASED_USE_IO_BITMAPS) &&
        (!vmx_addr_valid(env, VMCS(IO_BITMAP_A), 4096) ||
         !vmx_addr_valid(env, VMCS(IO_BITMAP_B), 4096))) {
        return false;
    }
    if ((proc & VMX_CPU_BASED_USE_MSR_BITMAPS) &&
        !vmx_addr_valid(env, VMCS(MSR_BITMAP), 4096)) {
        return false;
    }
    if (proc & VMX_CPU_BASED_TPR_SHADOW) {
        uint64_t vapic = VMCS(VIRTUAL_APIC_ADDR);
        uint64_t threshold = VMCS(TPR_THRESHOLD);

        if (!vmx_addr_valid(env, vapic, 4096)) {
            return false;
        }
        if (!(proc2 & VMX_SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY) &&
            ((threshold & ~0xfULL) ||
             (!(proc2 & VMX_SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES) &&
              threshold > x86_ldub_phys(env_cpu(env), vapic + 0x80) >> 4))) {
            return false;
        }
    } else if ((proc2 & (VMX_SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE |
                         VMX_SECONDARY_EXEC_APIC_REGISTER_VIRT |
                         VMX_SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY)) ||
               (proc3 & VMX_TERTIARY_EXEC_IPI_VIRT)) {
        return false;
    }
    if ((proc3 & VMX_TERTIARY_EXEC_IPI_VIRT) &&
        (!vmx_addr_valid(env, VMCS(PID_TABLE_ADDR), 8) ||
         !vmx_addr_valid(env, VMCS(PID_TABLE_ADDR) +
                              8 * VMCS(LAST_PID_INDEX), 8))) {
        return false;
    }
    if ((proc2 & VMX_SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES) &&
        !vmx_addr_valid(env, VMCS(APIC_ACCESS_ADDR), 4096)) {
        return false;
    }
    if ((proc2 & VMX_SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE) &&
        (proc2 & VMX_SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES)) {
        return false;
    }
    if ((proc2 & VMX_SECONDARY_EXEC_SHADOW_VMCS) &&
        (!vmx_addr_valid(env, VMCS(VMREAD_BITMAP), 4096) ||
         !vmx_addr_valid(env, VMCS(VMWRITE_BITMAP), 4096))) {
        return false;
    }
    if ((proc2 & VMX_SECONDARY_EXEC_TSC_SCALING) && !VMCS(TSC_MULTIPLIER)) {
        return false;
    }
    if ((proc2 & VMX_SECONDARY_EXEC_ENABLE_PML) &&
        (!(proc2 & VMX_SECONDARY_EXEC_ENABLE_EPT) ||
         !vmx_addr_valid(env, VMCS(PML_ADDR), 4096))) {
        return false;
    }
    if ((proc2 & VMX_SECONDARY_EXEC_ENABLE_VMFUNC) &&
        (VMCS(VMFUNC_CONTROLS) & ~env->features[FEAT_VMX_VMFUNC])) {
        return false;
    }
    if ((proc2 & VMX_SECONDARY_EXEC_ENABLE_VMFUNC) &&
        (VMCS(VMFUNC_CONTROLS) & MSR_VMX_VMFUNC_EPT_SWITCHING) &&
        (!(proc2 & VMX_SECONDARY_EXEC_ENABLE_EPT) ||
         !vmx_addr_valid(env, VMCS(EPTP_LIST_ADDR), 4096))) {
        return false;
    }
    if ((proc2 & VMX_SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY) &&
        !(pin & VMX_PIN_BASED_EXT_INTR_MASK)) {
        return false;
    }
    if ((pin & VMX_PIN_BASED_POSTED_INTR) &&
        (!(proc2 & VMX_SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY) ||
         !(exit_ctl & VMX_VM_EXIT_ACK_INTR_ON_EXIT) ||
         (VMCS(PI_NOTIFICATION_VECTOR) & 0xff00) ||
         !vmx_addr_valid(env, VMCS(PI_DESC_ADDR), 64))) {
        return false;
    }
    if (!(pin & VMX_PIN_BASED_NMI_EXITING) &&
        (pin & VMX_PIN_BASED_VIRTUAL_NMIS)) {
        return false;
    }
    if (!(pin & VMX_PIN_BASED_VIRTUAL_NMIS) &&
        (proc & VMX_CPU_BASED_VIRTUAL_NMI_PENDING)) {
        return false;
    }
    if ((exit_ctl & VMX_VM_EXIT_SAVE_VMX_PREEMPTION_TIMER) &&
        !(pin & VMX_PIN_BASED_VMX_PREEMPTION_TIMER)) {
        return false;
    }
    if (!vmx_msr_area_valid(env, VMCS(EXIT_MSR_STORE_ADDR),
                            VMCS(EXIT_MSR_STORE_COUNT)) ||
        !vmx_msr_area_valid(env, VMCS(EXIT_MSR_LOAD_ADDR),
                            VMCS(EXIT_MSR_LOAD_COUNT)) ||
        !vmx_msr_area_valid(env, VMCS(ENTRY_MSR_LOAD_ADDR),
                            VMCS(ENTRY_MSR_LOAD_COUNT))) {
        return false;
    }
    if ((entry_ctl & (VMX_VM_ENTRY_SMM | VMX_VM_ENTRY_DEACT_DUAL_MONITOR))) {
        return false;
    }
    if ((proc2 & VMX_SECONDARY_EXEC_ENABLE_EPT) &&
        !vmx_eptp_valid(env, x86_vmcs_read(env, 0x201a))) {
        return false;
    }
    if ((proc2 & (VMX_SECONDARY_EXEC_UNRESTRICTED_GUEST |
                  VMX_SECONDARY_EXEC_MODE_BASED_EPT_EXEC)) &&
        !(proc2 & VMX_SECONDARY_EXEC_ENABLE_EPT)) {
        return false;
    }
    if ((proc2 & VMX_SECONDARY_EXEC_ENABLE_VPID) && !VMCS(VPID)) {
        return false;
    }
    return vmx_injection_valid(env);
}

static bool vmx_canonical(CPUX86State *env, uint64_t addr)
{
    int bits = env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_LA57 ? 57 : 48;

    return ((int64_t)addr << (64 - bits) >> (64 - bits)) == addr;
}

/*
 * Whether bits 63:N of an address are all alike, N the linear-address
 * width, as RIP and SSP fields need (Intel SDM 325462-093 Vol. 3C,
 * 29.3.1.4).
 */
static bool vmx_upper_identical(CPUX86State *env, uint64_t addr)
{
    int64_t high = (int64_t)addr >>
                   (env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_LA57 ? 57 : 48);

    return high == 0 || high == -1;
}

/* CR3's reserved bits: those past MAXPHYADDR, but for LAM's 62:61. */
static uint64_t vmx_cr3_reserved(CPUX86State *env)
{
    uint64_t mask = ~0ULL << env_archcpu(env)->phys_bits;

    if (env->features[FEAT_7_1_EAX] & CPUID_7_1_EAX_LAM) {
        mask &= ~(3ULL << 61);
    }
    return mask;
}

/* A PAT value of memory types WRMSR takes in every byte. */
static bool vmx_pat_valid(uint64_t pat)
{
    for (int i = 0; i < 8; i++) {
        uint8_t type = pat >> (8 * i);

        if (type == 2 || type == 3 || type > 7) {
            return false;
        }
    }
    return true;
}

/*
 * The host-state area (Intel SDM 325462-093 Vol. 3C, 29.2.2 to 29.2.4),
 * on a processor with Intel 64 architecture.
 */
static bool vmx_host_state_valid(CPUX86State *env)
{
    uint32_t exit_ctl = VMCS(EXIT_CONTROLS);
    bool host64 = exit_ctl & VMX_VM_EXIT_HOST_ADDR_SPACE_SIZE;
    uint64_t cr0 = VMCS(HOST_CR0), cr4 = VMCS(HOST_CR4);
    uint64_t efer = VMCS(HOST_EFER);

    if (!x86_vmx_cr_valid(env, 0, cr0) || !x86_vmx_cr_valid(env, 4, cr4) ||
        ((cr4 & CR4_CET_MASK) && !(cr0 & CR0_WP_MASK)) ||
        (VMCS(HOST_CR3) & vmx_cr3_reserved(env)) ||
        !vmx_canonical(env, VMCS(HOST_SYSENTER_ESP)) ||
        !vmx_canonical(env, VMCS(HOST_SYSENTER_EIP))) {
        return false;
    }
    if ((exit_ctl & VMX_VM_EXIT_LOAD_IA32_PAT) &&
        !vmx_pat_valid(VMCS(HOST_PAT))) {
        return false;
    }
    if ((exit_ctl & VMX_VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL) &&
        !x86_pmu_global_ctrl_valid(VMCS(HOST_PERF_GLOBAL_CTRL))) {
        return false;
    }
    if ((exit_ctl & VMX_VM_EXIT_LOAD_IA32_EFER) &&
        ((efer & ~(x86_efer_writable(env) | MSR_EFER_LMA)) ||
         !!(efer & MSR_EFER_LMA) != host64 ||
         !!(efer & MSR_EFER_LME) != host64)) {
        return false;
    }
    for (int i = R_ES; i <= R_GS; i++) {
        if (x86_vmcs_read(env, VMCS_HOST_SEL(i)) & 7) {
            return false;
        }
    }
    if ((VMCS(HOST_TR_SEL) & 7) || !VMCS(HOST_TR_SEL) ||
        !VMCS(HOST_SEL(R_CS)) || (!host64 && !VMCS(HOST_SEL(R_SS)))) {
        return false;
    }
    if (!vmx_canonical(env, VMCS(HOST_FS_BASE)) ||
        !vmx_canonical(env, VMCS(HOST_GS_BASE)) ||
        !vmx_canonical(env, VMCS(HOST_TR_BASE)) ||
        !vmx_canonical(env, VMCS(HOST_GDTR_BASE)) ||
        !vmx_canonical(env, VMCS(HOST_IDTR_BASE))) {
        return false;
    }
    /*
     * The address-space size, from EFER.LMA at the VM entry
     * (Intel SDM 325462-093 Vol. 3C, 29.2.4).
     */
    if (env->efer & MSR_EFER_LMA ? !host64
                                 : host64 || (VMCS(ENTRY_CONTROLS) &
                                              VMX_VM_ENTRY_IA32E_MODE)) {
        return false;
    }
    if (host64) {
        return (cr4 & CR4_PAE_MASK) && vmx_canonical(env, VMCS(HOST_RIP));
    }
    return !(cr4 & CR4_PCIDE_MASK) && !(VMCS(HOST_RIP) >> 32);
}

/*
 * The events a VM entry may inject into an activity state (Intel SDM 325462-093
 * Vol. 3C, 29.3.1.5).
 */
static bool vmx_injection_allowed(uint32_t activity, uint32_t info)
{
    uint32_t type = (info & VMX_INTR_TYPE_MASK) >> VMX_INTR_TYPE_SHIFT;
    int vector = info & VMX_INTR_VECTOR_MASK;

    switch (activity) {
    case VMX_ACTIVITY_ACTIVE:
        return true;
    case VMX_ACTIVITY_HLT:
        return type == VMX_INTR_TYPE_EXT_INTR || type == VMX_INTR_TYPE_NMI ||
               (type == VMX_INTR_TYPE_HW_EXCEPTION &&
                (vector == EXCP01_DB || vector == EXCP12_MCHK)) ||
               (type == VMX_INTR_TYPE_OTHER && vector == 0);
    case VMX_ACTIVITY_SHUTDOWN:
        return type == VMX_INTR_TYPE_NMI ||
               (type == VMX_INTR_TYPE_HW_EXCEPTION && vector == EXCP12_MCHK);
    default:
        return false;
    }
}

/* The G bit agrees with the limit (Intel SDM 325462-093 Vol. 3C, 29.3.1.2). */
static bool vmx_granular(uint32_t ar, uint32_t limit)
{
    return ((limit & 0xfff) == 0xfff || !(ar & VMX_AR_G)) &&
           (!(limit >> 20) || (ar & VMX_AR_G));
}

/*
 * The checks of a usable data segment or of CS that all share (Intel SDM
 * 325462-093 Vol. 3C, 29.3.1.2): S, P, the reserved bits, and G.
 */
static bool vmx_segment_common(uint32_t ar, uint32_t limit)
{
    return (ar & VMX_AR_S) && (ar & VMX_AR_P) && !(ar & VMX_AR_RESERVED) &&
           vmx_granular(ar, limit);
}

/*
 * The guest's segment registers (Intel SDM 325462-093 Vol. 3C, 29.3.1.2),
 * on a processor with Intel 64 architecture.
 */
static bool vmx_guest_segments_valid(CPUX86State *env, bool ia32e, bool ug,
                                     uint64_t cr0, uint64_t rflags)
{
    uint32_t cs_ar = VMCS(GUEST_AR(R_CS)), ss_ar = VMCS(GUEST_AR(R_SS));
    uint32_t tr_ar = VMCS(GUEST_AR(R_TR));
    uint32_t ldtr_ar = VMCS(GUEST_AR(R_LDTR));
    uint32_t cs_type = VMX_AR_TYPE(cs_ar), tr_type = VMX_AR_TYPE(tr_ar);
    uint32_t ss_rpl = VMCS(GUEST_SEL(R_SS)) & 3;

    if (rflags & VM_MASK) {
        for (int i = R_ES; i <= R_GS; i++) {
            if (VMCS(GUEST_BASE(i)) != VMCS(GUEST_SEL(i)) << 4 ||
                VMCS(GUEST_LIMIT(i)) != 0xffff || VMCS(GUEST_AR(i)) != 0xf3) {
                return false;
            }
        }
    } else {
        if (!(cs_type == 9 || cs_type == 11 || cs_type == 13 ||
              cs_type == 15 || (ug && cs_type == 3)) ||
            !vmx_segment_common(cs_ar, VMCS(GUEST_LIMIT(R_CS))) ||
            (cs_type == 3 && VMX_AR_DPL(cs_ar)) ||
            ((cs_type == 9 || cs_type == 11) &&
             VMX_AR_DPL(cs_ar) != VMX_AR_DPL(ss_ar)) ||
            ((cs_type == 13 || cs_type == 15) &&
             VMX_AR_DPL(cs_ar) > VMX_AR_DPL(ss_ar)) ||
            (ia32e && (cs_ar & VMX_AR_L) && (cs_ar & VMX_AR_DB))) {
            return false;
        }
        if ((!ug && (ss_rpl != (VMCS(GUEST_SEL(R_CS)) & 3) ||
                     VMX_AR_DPL(ss_ar) != ss_rpl)) ||
            ((cs_type == 3 || !(cr0 & CR0_PE_MASK)) && VMX_AR_DPL(ss_ar))) {
            return false;
        }
        if (!(ss_ar & VMX_AR_UNUSABLE) &&
            ((VMX_AR_TYPE(ss_ar) != 3 && VMX_AR_TYPE(ss_ar) != 7) ||
             !vmx_segment_common(ss_ar, VMCS(GUEST_LIMIT(R_SS))))) {
            return false;
        }
        for (int i = R_ES; i <= R_GS; i++) {
            uint32_t ar = x86_vmcs_read(env, VMCS_GUEST_AR(i));
            uint32_t type = VMX_AR_TYPE(ar);

            if (i == R_CS || i == R_SS || (ar & VMX_AR_UNUSABLE)) {
                continue;
            }
            if (!(type & 1) || ((type & 8) && !(type & 2)) ||
                !vmx_segment_common(ar, x86_vmcs_read(env,
                                                      VMCS_GUEST_LIMIT(i))) ||
                (!ug && type <= 11 && VMX_AR_DPL(ar) <
                 (x86_vmcs_read(env, VMCS_GUEST_SEL(i)) & 3))) {
                return false;
            }
        }
    }
    if ((VMCS(GUEST_SEL(R_TR)) & 4) ||
        (ia32e ? tr_type != 11 : tr_type != 3 && tr_type != 11) ||
        (tr_ar & (VMX_AR_S | VMX_AR_UNUSABLE | VMX_AR_RESERVED)) ||
        !(tr_ar & VMX_AR_P) ||
        !vmx_granular(tr_ar, VMCS(GUEST_LIMIT(R_TR)))) {
        return false;
    }
    if (!(ldtr_ar & VMX_AR_UNUSABLE) &&
        ((VMCS(GUEST_SEL(R_LDTR)) & 4) || VMX_AR_TYPE(ldtr_ar) != 2 ||
         (ldtr_ar & (VMX_AR_S | VMX_AR_RESERVED)) || !(ldtr_ar & VMX_AR_P) ||
         !vmx_granular(ldtr_ar, VMCS(GUEST_LIMIT(R_LDTR))) ||
         !vmx_canonical(env, VMCS(GUEST_BASE(R_LDTR))))) {
        return false;
    }
    if (!vmx_canonical(env, VMCS(GUEST_BASE(R_TR))) ||
        !vmx_canonical(env, VMCS(GUEST_BASE(R_FS))) ||
        !vmx_canonical(env, VMCS(GUEST_BASE(R_GS))) ||
        (VMCS(GUEST_BASE(R_CS)) >> 32)) {
        return false;
    }
    for (int i = R_ES; i <= R_DS; i++) {
        if (i != R_CS &&
            !(x86_vmcs_read(env, VMCS_GUEST_AR(i)) & VMX_AR_UNUSABLE) &&
            (x86_vmcs_read(env, VMCS_GUEST_BASE(i)) >> 32)) {
            return false;
        }
    }
    return true;
}

/*
 * The PDPTEs of a guest with PAE paging, from the VMCS with EPT, else from
 * CR3 (Intel SDM 325462-093 Vol. 3C, 29.3.1.6): a present one must leave
 * its reserved bits clear.
 */
static bool vmx_guest_pdptes_valid(CPUX86State *env)
{
    uint64_t reserved = (~0ULL << env_archcpu(env)->phys_bits) | 0x1e6;
    bool ept = vmx_proc2(env) & VMX_SECONDARY_EXEC_ENABLE_EPT;
    hwaddr pdpt = VMCS(GUEST_CR3) & ~0x1fULL;

    for (int i = 0; i < 4; i++) {
        uint64_t pdpte = ept ? x86_vmcs_read(env, VMCS_GUEST_PDPTE(i))
                             : x86_ldq_phys(env_cpu(env), pdpt + 8 * i);

        if ((pdpte & PG_PRESENT_MASK) && (pdpte & reserved)) {
            return false;
        }
    }
    return true;
}

/*
 * The guest-state area (Intel SDM 325462-093 Vol. 3C, 29.3.1), on a processor
 * with Intel 64 architecture, also refusing what TCG lacks (SMM entry, SGX,
 * RTM). Returns the exit qualification plus 1 (Intel SDM 325462-093 Vol. 3C,
 * 29.8), or 0 where the state is good.
 */
static int vmx_guest_state_check(CPUX86State *env)
{
    uint32_t entry_ctl = VMCS(ENTRY_CONTROLS);
    bool ia32e = entry_ctl & VMX_VM_ENTRY_IA32E_MODE;
    bool ug = vmx_proc2(env) & VMX_SECONDARY_EXEC_UNRESTRICTED_GUEST;
    uint64_t cr0 = VMCS(GUEST_CR0), cr4 = VMCS(GUEST_CR4);
    uint64_t rflags = VMCS(GUEST_RFLAGS);
    uint32_t intr = VMCS(GUEST_INTERRUPTIBILITY);
    uint32_t activity = VMCS(GUEST_ACTIVITY);
    uint32_t info = VMCS(ENTRY_INTR_INFO);
    uint32_t type = (info & VMX_INTR_TYPE_MASK) >> VMX_INTR_TYPE_SHIFT;
    uint64_t pending = VMCS(GUEST_PENDING_DBG);
    uint64_t fixed0 = vmx_cr_fixed0(0);
    uint64_t link = VMCS(LINK_POINTER);
    uint64_t debugctl = VMCS(GUEST_DEBUGCTL);
    bool injecting = info & VMX_INTR_VALID;

    /*
     * Control registers, debug registers, and MSRs (Intel SDM 325462-093
     * Vol. 3C, 29.3.1.1).
     */
    if (ug) {
        fixed0 &= ~(CR0_PE_MASK | CR0_PG_MASK);
    }
    if ((cr0 & fixed0) != fixed0 || (cr0 >> 32) ||
        ((cr0 & CR0_PG_MASK) && !(cr0 & CR0_PE_MASK)) ||
        !x86_vmx_cr_valid(env, 4, cr4) ||
        ((cr4 & CR4_CET_MASK) && !(cr0 & CR0_WP_MASK)) ||
        (VMCS(GUEST_CR3) & vmx_cr3_reserved(env))) {
        return 1;
    }
    if (ia32e ? !(cr0 & CR0_PG_MASK) || !(cr4 & CR4_PAE_MASK)
              : !!(cr4 & (CR4_PCIDE_MASK | CR4_FRED_MASK))) {
        return 1;
    }
    if ((entry_ctl & VMX_VM_ENTRY_LOAD_DEBUG_CONTROLS) &&
        ((VMCS(GUEST_DR7) >> 32) ||
         (debugctl & ~(DEBUGCTL_LBR | DEBUGCTL_BTF)))) {
        return 1;
    }
    if (!vmx_canonical(env, VMCS(GUEST_SYSENTER_ESP)) ||
        !vmx_canonical(env, VMCS(GUEST_SYSENTER_EIP))) {
        return 1;
    }
    if ((entry_ctl & VMX_VM_ENTRY_LOAD_IA32_PAT) &&
        !vmx_pat_valid(VMCS(GUEST_PAT))) {
        return 1;
    }
    if ((entry_ctl & VMX_VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL) &&
        !x86_pmu_global_ctrl_valid(VMCS(GUEST_PERF_GLOBAL_CTRL))) {
        return 1;
    }
    if (entry_ctl & VMX_VM_ENTRY_LOAD_IA32_EFER) {
        uint64_t efer = VMCS(GUEST_EFER);

        if ((efer & ~(x86_efer_writable(env) | MSR_EFER_LMA)) ||
            !!(efer & MSR_EFER_LMA) != ia32e ||
            ((cr0 & CR0_PG_MASK) && !!(efer & MSR_EFER_LME) != ia32e)) {
            return 1;
        }
    }

    /*
     * Segment and descriptor-table registers (Intel SDM 325462-093 Vol. 3C,
     * 29.3.1.2 and 29.3.1.3).
     */
    if (!vmx_guest_segments_valid(env, ia32e, ug, cr0, rflags) ||
        !vmx_canonical(env, VMCS(GUEST_GDTR_BASE)) ||
        !vmx_canonical(env, VMCS(GUEST_IDTR_BASE)) ||
        (VMCS(GUEST_GDTR_LIMIT) >> 16) || (VMCS(GUEST_IDTR_LIMIT) >> 16)) {
        return 1;
    }

    /* RIP and RFLAGS (Intel SDM 325462-093 Vol. 3C, 29.3.1.4). */
    if (ia32e && (VMCS(GUEST_AR(R_CS)) & VMX_AR_L) ?
        !vmx_upper_identical(env, VMCS(GUEST_RIP)) : VMCS(GUEST_RIP) >> 32) {
        return 1;
    }
    if ((rflags >> 22) || (rflags & 0x8028) || !(rflags & 2) ||
        ((rflags & VM_MASK) && (ia32e || !(cr0 & CR0_PE_MASK))) ||
        (injecting && type == VMX_INTR_TYPE_EXT_INTR &&
         !(rflags & IF_MASK))) {
        return 1;
    }

    /* Non-register state (Intel SDM 325462-093 Vol. 3C, 29.3.1.5). */
    if (activity > VMX_ACTIVITY_WAIT_SIPI ||
        (activity == VMX_ACTIVITY_HLT &&
         !(env->features[FEAT_VMX_MISC] & MSR_VMX_MISC_ACTIVITY_HLT)) ||
        (activity == VMX_ACTIVITY_SHUTDOWN &&
         !(env->features[FEAT_VMX_MISC] & MSR_VMX_MISC_ACTIVITY_SHUTDOWN)) ||
        (activity == VMX_ACTIVITY_WAIT_SIPI &&
         !(env->features[FEAT_VMX_MISC] & MSR_VMX_MISC_ACTIVITY_WAIT_SIPI)) ||
        (activity == VMX_ACTIVITY_HLT &&
         VMX_AR_DPL(VMCS(GUEST_AR(R_SS)))) ||
        (activity != VMX_ACTIVITY_ACTIVE &&
         (intr & (VMX_BLOCKING_STI | VMX_BLOCKING_MOV_SS))) ||
        (injecting && !vmx_injection_allowed(activity, info))) {
        return 1;
    }
    if ((intr >> 4) || (intr & 3) == 3 ||
        ((intr & VMX_BLOCKING_STI) && !(rflags & IF_MASK)) ||
        ((intr & VMX_BLOCKING_SMI) && !(env->hflags & HF_SMM_MASK))) {
        return 1;
    }
    if (injecting && (type == VMX_INTR_TYPE_EXT_INTR ||
                      type == VMX_INTR_TYPE_NMI) && (intr & 3)) {
        return type == VMX_INTR_TYPE_NMI && (intr & VMX_BLOCKING_STI) ? 4 : 1;
    }
    if (injecting && type == VMX_INTR_TYPE_NMI &&
        (VMCS(PIN_CONTROLS) & VMX_PIN_BASED_VIRTUAL_NMIS) &&
        (intr & VMX_BLOCKING_NMI)) {
        return 1;
    }
    if ((pending & ~(uint64_t)(VMX_DB_BITS | VMX_PENDING_DBG_ENABLED_BP)) ||
        (pending & (DR6_BD | VMX_PENDING_DBG_RTM))) {
        return 1;
    }
    if (((intr & 3) || activity == VMX_ACTIVITY_HLT) &&
        !!(pending & DR6_BS) !=
        ((rflags & TF_MASK) && !(debugctl & DEBUGCTL_BTF))) {
        return 1;
    }
    if (link != ~0ULL &&
        (!vmx_addr_valid(env, link, 4096) || link == env->vmx.vmcs_ptr ||
         x86_ldl_phys(env_cpu(env), link) !=
         (VMX_VMCS_REVISION |
          (vmx_proc2(env) & VMX_SECONDARY_EXEC_SHADOW_VMCS ? 1u << 31 : 0)))) {
        return 5;
    }

    /* PDPTEs (Intel SDM 325462-093 Vol. 3C, 29.3.1.6). */
    if ((cr0 & CR0_PG_MASK) && (cr4 & CR4_PAE_MASK) && !ia32e &&
        !vmx_guest_pdptes_valid(env)) {
        return 3;
    }
    return 0;
}

/*
 * The entry injects an event, the pending MTF VM exits of type other
 * event aside (Intel SDM 325462-093 Vol. 3C, 29.7).
 */
static bool vmx_injecting(CPUX86State *env)
{
    uint32_t info = VMCS(ENTRY_INTR_INFO);

    return (info & VMX_INTR_VALID) &&
           (info & VMX_INTR_TYPE_MASK) !=
           VMX_INTR_TYPE_OTHER << VMX_INTR_TYPE_SHIFT;
}

/* The guest state a VM entry loads (Intel SDM 325462-093 Vol. 3C, 29.3.2). */
static void vmx_load_guest(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);
    uint32_t entry_ctl = VMCS(ENTRY_CONTROLS);
    uint32_t intr = VMCS(GUEST_INTERRUPTIBILITY);
    uint64_t efer;

    if (entry_ctl & VMX_VM_ENTRY_LOAD_IA32_EFER) {
        efer = VMCS(GUEST_EFER);
    } else {
        efer = env->efer & ~(MSR_EFER_LMA | MSR_EFER_LME);
        if (entry_ctl & VMX_VM_ENTRY_IA32E_MODE) {
            efer |= MSR_EFER_LMA | MSR_EFER_LME;
        }
    }
    env->svm_loading_crs = true;
    cpu_x86_update_cr0(env, VMCS(GUEST_CR0));
    cpu_x86_update_cr4(env, VMCS(GUEST_CR4));
    cpu_x86_update_cr3(env, VMCS(GUEST_CR3));
    env->svm_loading_crs = false;
    cpu_load_efer(env, efer);
    if (entry_ctl & VMX_VM_ENTRY_LOAD_DEBUG_CONTROLS) {
        cpu_x86_update_dr7(env, VMCS(GUEST_DR7));
        env->debugctl = VMCS(GUEST_DEBUGCTL);
    }
    env->sysenter_cs = (uint32_t)VMCS(GUEST_SYSENTER_CS);
    env->sysenter_esp = VMCS(GUEST_SYSENTER_ESP);
    env->sysenter_eip = VMCS(GUEST_SYSENTER_EIP);
    if (entry_ctl & VMX_VM_ENTRY_LOAD_IA32_PAT) {
        env->pat = VMCS(GUEST_PAT);
    }
    if (entry_ctl & VMX_VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL) {
        x86_pmu_set_global_ctrl(env, VMCS(GUEST_PERF_GLOBAL_CTRL));
    }

    env->eflags = 0;
    cpu_load_eflags(env, VMCS(GUEST_RFLAGS),
                    ~(CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C | DF_MASK));
    env->cc_op = CC_OP_EFLAGS;
    for (int i = 0; i < 8; i++) {
        cpu_x86_load_seg_cache(env, i,
                               x86_vmcs_read(env, VMCS_GUEST_SEL(i)),
                               x86_vmcs_read(env, VMCS_GUEST_BASE(i)),
                               x86_vmcs_read(env, VMCS_GUEST_LIMIT(i)),
                               vmx_flags(x86_vmcs_read(env,
                                                       VMCS_GUEST_AR(i))));
    }
    env->gdt.base = VMCS(GUEST_GDTR_BASE);
    env->gdt.limit = VMCS(GUEST_GDTR_LIMIT);
    env->idt.base = VMCS(GUEST_IDTR_BASE);
    env->idt.limit = VMCS(GUEST_IDTR_LIMIT);
    env->eip = VMCS(GUEST_RIP);
    env->regs[R_ESP] = VMCS(GUEST_RSP);

    env->hflags &= ~HF_INHIBIT_IRQ_MASK;
    if (intr & (VMX_BLOCKING_STI | VMX_BLOCKING_MOV_SS)) {
        env->hflags |= HF_INHIBIT_IRQ_MASK;
    }
    env->shadow_movss = intr & VMX_BLOCKING_MOV_SS;
    if (VMCS(PIN_CONTROLS) & VMX_PIN_BASED_VIRTUAL_NMIS) {
        env->vmx.vnmi_blocked = intr & VMX_BLOCKING_NMI;
    } else if (intr & VMX_BLOCKING_NMI) {
        env->hflags2 |= HF2_NMI_MASK;
    } else {
        env->hflags2 &= ~HF2_NMI_MASK;
    }
    /*
     * PAE paging under EPT takes its PDPTEs from the VMCS (Intel SDM 325462-093
     * Vol. 3C, 29.3.2.4).
     */
    if ((vmx_proc2(env) & VMX_SECONDARY_EXEC_ENABLE_EPT) &&
        (env->cr[0] & CR0_PG_MASK) && (env->cr[4] & CR4_PAE_MASK) &&
        !(env->efer & MSR_EFER_LMA)) {
        for (int i = 0; i < 4; i++) {
            env->vmx.pdpte[i] = x86_vmcs_read(env, VMCS_GUEST_PDPTE(i));
        }
        env->vmx.pdpte_loaded = true;
    }
    /*
     * An entry that injects ends active (Intel SDM 325462-093 Vol. 3C,
     * 29.7.2); one making an MTF VM exit pending does not inject (Intel SDM
     * 325462-093 Vol. 3C, 29.7). The HLT, shutdown, and wait-for-SIPI states
     * halt the processor, the last two noted for the events they block.
     */
    cs->halted = VMCS(GUEST_ACTIVITY) != VMX_ACTIVITY_ACTIVE &&
                 !vmx_injecting(env);
    env->vmx.inactive = cs->halted &&
                        VMCS(GUEST_ACTIVITY) != VMX_ACTIVITY_HLT ?
                        VMCS(GUEST_ACTIVITY) : 0;
    env->vmx.hlt_wake = false;
    env->vmx.exit_hlt = false;
}

/*
 * The event a VM entry injects (Intel SDM 325462-093 Vol. 3C, 29.6.1),
 * delivered through the guest's IDT as the processor delivers events:
 * software interrupts and exceptions return past an instruction of the
 * VM-entry instruction length.
 */
static void vmx_inject(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);
    uint32_t info = VMCS(ENTRY_INTR_INFO);
    int vector = info & VMX_INTR_VECTOR_MASK;
    uint32_t type = (info & VMX_INTR_TYPE_MASK) >> VMX_INTR_TYPE_SHIFT;

    if (!(info & VMX_INTR_VALID)) {
        return;
    }
    switch (type) {
    case VMX_INTR_TYPE_EXT_INTR:
        do_interrupt_x86_hardirq(env, vector, 1);
        cs->exception_index = -1;
        return;
    case VMX_INTR_TYPE_NMI:
        if (VMCS(PIN_CONTROLS) & VMX_PIN_BASED_VIRTUAL_NMIS) {
            env->vmx.vnmi_blocked = true;
        } else {
            env->hflags2 |= HF2_NMI_MASK;
        }
        do_interrupt_x86_hardirq(env, EXCP02_NMI, 1);
        cs->exception_index = -1;
        return;
    case VMX_INTR_TYPE_HW_EXCEPTION:
        cs->exception_index = vector;
        env->error_code = VMCS(ENTRY_EXCEPTION_ERROR);
        env->exception_is_int = 0;
        env->exception_next_eip = -1;
        if (vector == EXCP0E_PAGE || vector == EXCP08_DBLE ||
            vector == EXCP00_DIVZ || (vector >= 10 && vector <= 13)) {
            env->old_exception = vector;
        }
        break;
    case VMX_INTR_TYPE_OTHER:
        /* A pending MTF VM exit (Intel SDM 325462-093 Vol. 3C, 29.6.2). */
        env->vmx.mtf_pending = true;
        cpu_set_interrupt(cs, CPU_INTERRUPT_VMX);
        return;
    default:
        env->vmx.soft_exception = type == VMX_INTR_TYPE_SW_INTR ? 0 : type;
        cs->exception_index = vector;
        env->error_code = 0;
        env->exception_is_int = 1;
        env->exception_next_eip = env->eip + VMCS(ENTRY_INSN_LEN);
        break;
    }
    cpu_loop_exit(cs);
}

/*
 * The pending debug exceptions of a VM entry that injects nothing, into an
 * activity state that takes them (Intel SDM 325462-093 Vol. 3C, 29.7.3):
 * valid with BS or the enabled-breakpoint bit, they raise a #DB at once
 * or, under a MOV SS shadow, at its end.
 */
static void vmx_entry_debug(CPUX86State *env)
{
    uint64_t pending = VMCS(GUEST_PENDING_DBG);
    uint32_t activity = VMCS(GUEST_ACTIVITY);

    if (vmx_injecting(env) || activity == VMX_ACTIVITY_SHUTDOWN ||
        activity == VMX_ACTIVITY_WAIT_SIPI ||
        !(pending & (DR6_BS | VMX_PENDING_DBG_ENABLED_BP))) {
        return;
    }
    env->vmx.db_held = pending & VMX_DB_BITS;
    cpu_set_interrupt(env_cpu(env), CPU_INTERRUPT_VMX);
}

/* A VM-entry failure loads the host state with the exit reason only. */
static void vmx_entry_failure(CPUX86State *env, uint32_t reason,
                              uint64_t qual)
{
    VMCS_SET(EXIT_REASON, reason | VMX_EXIT_ENTRY_FAILURE);
    VMCS_SET(EXIT_QUALIFICATION, qual);
    VMCS_SET(EXIT_INTR_INFO, 0);
    vmx_load_host(env);
    if (vmx_msr_area_load(env, VMCS(EXIT_MSR_LOAD_ADDR),
                          VMCS(EXIT_MSR_LOAD_COUNT))) {
        vmx_abort(env, 4);
    }
}

/*
 * The guest's translations at a VM entry: without VPIDs, none survive, nor the
 * host's (Intel SDM 325462-093 Vol. 3C, 29.3.2.5); with them, those TCG keeps
 * of a guest of the same VPID, EPTP, APIC-access address, and paging state
 * stay, all others go.
 */
static void vmx_entry_tlb(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);
    uint64_t vpid = VMCS(VPID);
    uint64_t eptp = vmx_proc2(env) & VMX_SECONDARY_EXEC_ENABLE_EPT ?
                    x86_vmcs_read(env, 0x201a) : 0;

    if (!(vmx_proc2(env) & VMX_SECONDARY_EXEC_ENABLE_VPID)) {
        env->vmx.tlb_vpid = ~0ULL;
        tlb_flush(cs);
        return;
    }
    if (vpid != env->vmx.tlb_vpid || eptp != env->vmx.tlb_eptp ||
        env->vmx.apic_access != env->vmx.tlb_apic_access ||
        env->cr[0] != env->vmx.tlb_cr0 || env->cr[3] != env->vmx.tlb_cr3 ||
        env->cr[4] != env->vmx.tlb_cr4 || env->efer != env->vmx.tlb_efer) {
        tlb_flush_by_mmuidx(cs, MMU_GUEST_IDX_MAP | 1 << MMU_NESTED_IDX |
                                1 << MMU_NESTED_SUP_IDX);
        env->vmx.tlb_vpid = vpid;
        env->vmx.tlb_eptp = eptp;
        env->vmx.tlb_apic_access = env->vmx.apic_access;
    }
}

/*
 * INVEPT and INVVPID (Intel SDM 325462-093 Vol. 3C, Chapter 33): TCG keeps
 * the translations of one guest context, which both drop.
 */
static bool vmx_inv_check(CPUX86State *env, uintptr_t ra)
{
    if ((env->hflags & HF_LMA_MASK) && !(env->hflags & HF_CS64_MASK)) {
        raise_exception_ra(env, EXCP06_ILLOP, ra);
    }
    vmx_check_root(env, ra);
    return true;
}

void HELPER(invept)(CPUX86State *env, target_ulong ptr, target_ulong type,
                    int seg)
{
    uintptr_t ra = GETPC();
    uint64_t caps = env->features[FEAT_VMX_EPT_VPID_CAPS];
    uint64_t eptp;

    if (!(caps & MSR_VMX_EPT_INVEPT)) {
        raise_exception_ra(env, EXCP06_ILLOP, ra);
    }
    vmx_inv_check(env, ra);
    if (!((type == 1 && (caps & MSR_VMX_EPT_INVEPT_SINGLE_CONTEXT)) ||
          (type == 2 && (caps & MSR_VMX_EPT_INVEPT_ALL_CONTEXT)))) {
        vmx_fail(env, VMXERR_INV_OPERAND);
        return;
    }
    vmx_check_operand(env, ptr, 16, seg, ra);
    eptp = cpu_ldq_le_data_ra(env, ptr, ra);
    if (type == 1 && !vmx_eptp_valid(env, eptp)) {
        vmx_fail(env, VMXERR_INV_OPERAND);
        return;
    }
    tlb_flush(env_cpu(env));
    env->vmx.tlb_vpid = ~0ULL;
    vmx_succeed(env);
}

void HELPER(invvpid)(CPUX86State *env, target_ulong ptr, target_ulong type,
                     int seg)
{
    uintptr_t ra = GETPC();
    uint64_t caps = env->features[FEAT_VMX_EPT_VPID_CAPS];
    uint64_t desc, addr;

    if (!(caps & MSR_VMX_EPT_INVVPID)) {
        raise_exception_ra(env, EXCP06_ILLOP, ra);
    }
    vmx_inv_check(env, ra);
    if (type > 3 || !(caps & (MSR_VMX_EPT_INVVPID_SINGLE_ADDR << type))) {
        vmx_fail(env, VMXERR_INV_OPERAND);
        return;
    }
    vmx_check_operand(env, ptr, 16, seg, ra);
    desc = cpu_ldq_le_data_ra(env, ptr, ra);
    addr = cpu_ldq_le_data_ra(env, ptr + 8, ra);
    if ((desc >> 16) || (type != 2 && !(desc & 0xffff)) ||
        (type == 0 && !vmx_canonical(env, addr))) {
        vmx_fail(env, VMXERR_INV_OPERAND);
        return;
    }
    if (type == 0) {
        tlb_flush_page_by_mmuidx(env_cpu(env), addr, MMU_GUEST_IDX_MAP);
    } else {
        tlb_flush_by_mmuidx(env_cpu(env), MMU_GUEST_IDX_MAP);
    }
    vmx_succeed(env);
}

/*
 * VMLAUNCH and VMRESUME (Intel SDM 325462-093 Vol. 3C, Chapter 29): VMfail
 * for the checks of the controls and the host state, else the VM entry,
 * which may fail on the guest state or the MSRs it loads.
 */
void HELPER(vmlaunch)(CPUX86State *env, int resume, int next_eip_addend)
{
    CPUState *cs = env_cpu(env);
    uint32_t failed;
    int bad;

    vmx_check_root(env, GETPC());
    /* A shadow VMCS cannot be entered (Intel SDM 325462-093 Vol. 3C, 29.1). */
    if (env->vmx.vmcs_ptr == ~0ULL ||
        x86_ldl_phys(cs, env->vmx.vmcs_ptr) >> 31) {
        vmx_fail_invalid(env);
        goto vmfail;
    }
    if ((env->hflags & HF_INHIBIT_IRQ_MASK) && env->shadow_movss) {
        vmx_fail(env, VMXERR_ENTRY_MOV_SS);
        goto vmfail;
    }
    if (!resume && env->vmx.vmcs_launched) {
        vmx_fail(env, VMXERR_VMLAUNCH_NONCLEAR);
        goto vmfail;
    }
    if (resume && !env->vmx.vmcs_launched) {
        vmx_fail(env, VMXERR_VMRESUME_NONLAUNCHED);
        goto vmfail;
    }
    if (!vmx_controls_valid(env)) {
        vmx_fail(env, VMXERR_ENTRY_CONTROLS);
        goto vmfail;
    }
    if (!vmx_host_state_valid(env)) {
        vmx_fail(env, VMXERR_ENTRY_HOST_STATE);
        goto vmfail;
    }

    bad = vmx_guest_state_check(env);
    if (bad) {
        vmx_entry_failure(env, VMX_EXIT_INVALID_GUEST_STATE, bad - 1);
        return;
    }
    vmx_load_guest(env);
    env->vmx.nonroot = true;
    env->monitor_armed = false;
    env->umonitor_armed = false;
    env->hflags |= HF_GUEST_MASK;
    if (vmx_proc2(env) & VMX_SECONDARY_EXEC_ENABLE_EPT) {
        env->hflags2 |= HF2_NPT_MASK;
    }
    env->vmx.apic_access =
        vmx_proc2(env) & VMX_SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES ?
        VMCS(APIC_ACCESS_ADDR) : ~0ULL;
    vmx_entry_tlb(env);
    failed = vmx_msr_area_load(env, VMCS(ENTRY_MSR_LOAD_ADDR),
                               VMCS(ENTRY_MSR_LOAD_COUNT));
    if (failed) {
        env->vmx.nonroot = false;
        env->hflags &= ~HF_GUEST_MASK;
        vmx_entry_failure(env, VMX_EXIT_MSR_LOADING, failed);
        return;
    }
    env->vmx.vmcs_launched = 1;
    env->vmx.mtf = VMCS(PROC_CONTROLS) & VMX_CPU_BASED_MONITOR_TRAP_FLAG;
    env->vmx.ple_loop = false;
    if (VMCS(PIN_CONTROLS) & VMX_PIN_BASED_VMX_PREEMPTION_TIMER) {
        vmx_timer_start(env);
    }
    if (VMCS(PROC_CONTROLS) & (VMX_CPU_BASED_VIRTUAL_INTR_PENDING |
                               VMX_CPU_BASED_VIRTUAL_NMI_PENDING)) {
        cpu_set_interrupt(cs, CPU_INTERRUPT_VMX);
    }
    if (env->vmx.init_pending) {
        env->vmx.init_pending = false;
        cpu_set_interrupt(cs, CPU_INTERRUPT_INIT);
    }
    vmx_entry_debug(env);
    /*
     * With "use TPR shadow" and "virtualize APIC accesses", a TPR
     * threshold above VTPR[7:4] exits once the entry and its injection are
     * done (Intel SDM 325462-093 Vol. 3C, 29.7.7).
     */
    if ((VMCS(PROC_CONTROLS) & VMX_CPU_BASED_TPR_SHADOW) &&
        env->vmx.apic_access != ~0ULL && vmx_tpr_below_threshold(env)) {
        env->vmx.tpr_exit_pending = true;
        cpu_set_interrupt(cs, CPU_INTERRUPT_VMX);
    }
    /*
     * With virtual-interrupt delivery, PPR virtualization and an
     * evaluation of pending virtual interrupts, whose delivery may follow
     * the entry and its injection at once (Intel SDM 325462-093 Vol. 3C,
     * 29.3.2.5 and 29.7.5).
     */
    if (vmx_proc2(env) & VMX_SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY) {
        vmx_ppr_virtualize(env);
        vmx_vintr_evaluate(env);
    }
    vmx_inject(env);
    if (cs->halted) {
        cs->exception_index = EXCP_HLT;
        cpu_loop_exit(cs);
    }
    return;

vmfail:
    env->eip += next_eip_addend;
    env->cc_op = CC_OP_EFLAGS;
}

/*
 * The events of VMX non-root operation (Intel SDM 325462-093 Vol. 3C,
 * 27.6.1 and 27.6.2): external interrupts and NMIs exit regardless of
 * RFLAGS.IF and of NMI blocking where their exiting controls are set, as
 * Linux 7.3's KVM has it, but wait out STI and MOV SS shadows, which the
 * SDM leaves to the implementation (Intel SDM 325462-093 Vol. 3C, 28.4.1);
 * the interrupt and NMI windows exit once the guest could take one.
 */
int x86_vmx_pending_interrupt(const CPUX86State *env, int request)
{
    uint32_t pin = x86_vmcs_read((CPUX86State *)env, VMCS_PIN_CONTROLS);
    uint32_t proc = x86_vmcs_read((CPUX86State *)env, VMCS_PROC_CONTROLS);
    bool shadow = env->hflags & HF_INHIBIT_IRQ_MASK;

    if (request & CPU_INTERRUPT_POLL) {
        return CPU_INTERRUPT_POLL;
    }
    /*
     * The wait-for-SIPI state blocks all but SIPIs, which exit, and the
     * other states discard SIPIs; INIT signals exit from those, waking the
     * processor (Intel SDM 325462-093 Vol. 3C, 28.2 and 29.7.2).
     */
    if (env->vmx.inactive == VMX_ACTIVITY_WAIT_SIPI) {
        return request & CPU_INTERRUPT_SIPI;
    }
    if (request & CPU_INTERRUPT_INIT) {
        return CPU_INTERRUPT_INIT;
    }
    /*
     * The TPR-below-threshold VM exit after a VM entry comes before SMIs
     * (Intel SDM 325462-093 Vol. 3C, 29.7.7).
     */
    if ((request & CPU_INTERRUPT_VMX) && env->vmx.tpr_exit_pending) {
        return CPU_INTERRUPT_VMX;
    }
    if ((request & CPU_INTERRUPT_SMI) && !(env->hflags & HF_SMM_MASK)) {
        return CPU_INTERRUPT_SMI;
    }
    /*
     * The shutdown state blocks external and virtual interrupts, the
     * windows, and MTF VM exits, not NMIs, machine checks, or the
     * VMX-preemption timer (Intel SDM 325462-093 Vol. 3C, 28.5.1, 29.7.2,
     * 30.1, and 32.2.2).
     */
    if (env->vmx.inactive == VMX_ACTIVITY_SHUTDOWN) {
        if ((request & CPU_INTERRUPT_VMX) && vmx_timer_expired(env)) {
            return CPU_INTERRUPT_VMX;
        }
        if ((request & CPU_INTERRUPT_NMI) &&
            ((pin & VMX_PIN_BASED_NMI_EXITING) ||
             !(env->hflags2 & HF2_NMI_MASK))) {
            return CPU_INTERRUPT_NMI;
        }
        return request & CPU_INTERRUPT_MCE;
    }
    /*
     * MTF VM exits come after SMIs and INITs, before debug traps (Intel
     * SDM 325462-093 Vol. 3C, 28.5.2).
     */
    if ((request & CPU_INTERRUPT_VMX) && env->vmx.mtf_pending) {
        return CPU_INTERRUPT_VMX;
    }
    /* A held #DB has the priority of traps on the previous instruction. */
    if ((request & CPU_INTERRUPT_VMX) && env->vmx.db_held &&
        !(shadow && env->shadow_movss)) {
        return CPU_INTERRUPT_VMX;
    }
    /*
     * The VMX-preemption timer's exits come after debug traps, before the
     * NMI window and NMIs (Intel SDM 325462-093 Vol. 3C, 28.2).
     */
    if ((request & CPU_INTERRUPT_VMX) && vmx_timer_expired(env)) {
        return CPU_INTERRUPT_VMX;
    }
    /*
     * The NMI window goes before NMIs, the interrupt window before
     * external interrupts (Intel SDM 325462-093 Vol. 3C, 28.2).
     */
    if ((request & CPU_INTERRUPT_VMX) &&
        (proc & VMX_CPU_BASED_VIRTUAL_NMI_PENDING) &&
        !env->vmx.vnmi_blocked && !shadow) {
        return CPU_INTERRUPT_VMX;
    }
    if ((request & CPU_INTERRUPT_NMI) && !shadow &&
        ((pin & VMX_PIN_BASED_NMI_EXITING) ||
         !(env->hflags2 & HF2_NMI_MASK))) {
        return CPU_INTERRUPT_NMI;
    }
    if (request & CPU_INTERRUPT_MCE) {
        return CPU_INTERRUPT_MCE;
    }
    if ((request & CPU_INTERRUPT_VMX) &&
        (proc & VMX_CPU_BASED_VIRTUAL_INTR_PENDING) &&
        (env->eflags & IF_MASK) && !shadow) {
        return CPU_INTERRUPT_VMX;
    }
    /*
     * Virtual-interrupt delivery has the interrupt window's priority
     * (Intel SDM 325462-093 Vol. 3C, 32.2.2).
     */
    if ((request & CPU_INTERRUPT_VMX) && env->vmx.vintr_pending &&
        (env->eflags & IF_MASK) && !shadow) {
        return CPU_INTERRUPT_VMX;
    }
    if ((request & CPU_INTERRUPT_HARD) && !shadow &&
        ((pin & VMX_PIN_BASED_EXT_INTR_MASK) ||
         (env->eflags & IF_MASK))) {
        return CPU_INTERRUPT_HARD;
    }
    return 0;
}

/*
 * Takes the event x86_vmx_pending_interrupt() chose, where it exits;
 * false where the guest's IDT delivers it as usual.
 */
static bool vmx_take_interrupt(CPUX86State *env, int request)
{
    CPUState *cs = env_cpu(env);
    uint32_t pin = VMCS(PIN_CONTROLS);
    uint32_t proc = VMCS(PROC_CONTROLS);

    switch (request) {
    case CPU_INTERRUPT_SIPI:
        cpu_reset_interrupt(cs, CPU_INTERRUPT_SIPI);
        x86_vmx_exit(env, VMX_EXIT_SIPI,
                     apic_get_sipi_vector(env_archcpu(env)->apic_state), 0);
    case CPU_INTERRUPT_NMI:
        if (!(pin & VMX_PIN_BASED_NMI_EXITING)) {
            return false;
        }
        /* A second NMI stays pending behind this one. */
        if (env->nmi_second) {
            env->nmi_second = false;
        } else {
            cpu_reset_interrupt(cs, CPU_INTERRUPT_NMI);
        }
        x86_vmx_exit_full(env, VMX_EXIT_EXCEPTION_NMI, 0,
                          EXCP02_NMI | VMX_INTR_VALID |
                          VMX_INTR_TYPE_NMI << VMX_INTR_TYPE_SHIFT, 0, 0);
    case CPU_INTERRUPT_HARD:
        if (!(pin & VMX_PIN_BASED_EXT_INTR_MASK)) {
            return false;
        }
        if (VMCS(EXIT_CONTROLS) & VMX_VM_EXIT_ACK_INTR_ON_EXIT) {
            int intno;

            cpu_reset_interrupt(cs, CPU_INTERRUPT_HARD);
            intno = cpu_get_pic_interrupt(env);
            if ((pin & VMX_PIN_BASED_POSTED_INTR) &&
                intno == (int)VMCS(PI_NOTIFICATION_VECTOR)) {
                vmx_posted_interrupts(env);
                /*
                 * Out of the HLT state, the processor goes back to it but
                 * for a virtual interrupt it can deliver (Intel SDM
                 * 325462-093 Vol. 3C, 32.6).
                 */
                if (env->vmx.exit_hlt && !(env->vmx.vintr_pending &&
                                           (env->eflags & IF_MASK))) {
                    env->vmx.exit_hlt = false;
                    cs->halted = 1;
                    cs->exception_index = EXCP_HLT;
                    cpu_loop_exit(cs);
                }
                env->vmx.exit_hlt = false;
                return true;
            }
            x86_vmx_exit_full(env, VMX_EXIT_EXTERNAL_INTERRUPT, 0,
                              intno | VMX_INTR_VALID, 0, 0);
        }
        x86_vmx_exit(env, VMX_EXIT_EXTERNAL_INTERRUPT, 0, 0);
    case CPU_INTERRUPT_VMX:
        /*
         * Right after the entry, the debug exceptions it left pending stay
         * so through the exits ahead of them (Intel SDM 325462-093 Vol. 3C,
         * 30.3.4).
         */
        if (env->vmx.db_held &&
            (env->vmx.tpr_exit_pending || env->vmx.mtf_pending)) {
            env->vmx.exit_pending_dbg = VMCS(GUEST_PENDING_DBG) &
                                        (VMX_DB_BITS |
                                         VMX_PENDING_DBG_ENABLED_BP);
        }
        if (env->vmx.tpr_exit_pending) {
            env->vmx.tpr_exit_pending = false;
            x86_vmx_exit(env, VMX_EXIT_TPR_BELOW_THRESHOLD, 0, 0);
        }
        if (env->vmx.mtf_pending) {
            env->vmx.mtf_pending = false;
            x86_vmx_exit(env, VMX_EXIT_MONITOR_TRAP_FLAG, 0, 0);
        }
        if (env->vmx.db_held && !((env->hflags & HF_INHIBIT_IRQ_MASK) &&
                                  env->shadow_movss)) {
            env->vmx.exit_hlt = false;
            raise_debug_exception(env, 0, 0);
        }
        if (vmx_timer_expired(env)) {
            x86_vmx_exit(env, VMX_EXIT_PREEMPTION_TIMER, 0, 0);
        }
        if ((proc & VMX_CPU_BASED_VIRTUAL_NMI_PENDING) &&
            !env->vmx.vnmi_blocked && !(env->hflags & HF_INHIBIT_IRQ_MASK)) {
            x86_vmx_exit(env, VMX_EXIT_NMI_WINDOW, 0, 0);
        }
        if (env->vmx.vintr_pending) {
            env->vmx.exit_hlt = false;
            vmx_vintr_deliver(env);
            return true;
        }
        x86_vmx_exit(env, VMX_EXIT_INTERRUPT_WINDOW, 0, 0);
    default:
        return false;
    }
}

/*
 * An event that exits directly out of an inactive state, which it woke the
 * processor from, leaves that state only once the exit completes, so the
 * exit saves it; one delivered as usual makes the processor active (Intel
 * SDM 325462-093 Vol. 3C, 30.1).
 */
bool x86_vmx_take_interrupt(CPUX86State *env, int request, bool woke)
{
    env->vmx.exit_hlt = woke;
    if (vmx_take_interrupt(env, request)) {
        return true;
    }
    env->vmx.exit_hlt = false;
    env->vmx.inactive = 0;
    return false;
}

bool x86_vmx_virtual_nmis(CPUX86State *env)
{
    return VMCS(PIN_CONTROLS) & VMX_PIN_BASED_VIRTUAL_NMIS;
}

/*
 * RDTSCP and RDPID need "enable RDTSCP" in non-root operation
 * (Intel SDM 325462-093 Vol. 3C, 28.3).
 */
bool x86_vmx_rdtscp_allowed(CPUX86State *env)
{
    return vmx_proc2(env) & VMX_SECONDARY_EXEC_RDTSCP;
}

/*
 * The TSC non-root operation reads, with "use TSC offsetting": scaled
 * first, with "use TSC scaling", by the TSC multiplier, a 16.48 fixed
 * point number (Intel SDM 325462-093 Vol. 3C, 27.6.5 and 28.3).
 */
uint64_t x86_vmx_tsc(CPUX86State *env, uint64_t tsc)
{
    uint64_t low, high;

    if (!(VMCS(PROC_CONTROLS) & VMX_CPU_BASED_USE_TSC_OFFSETING)) {
        return tsc;
    }
    if (vmx_proc2(env) & VMX_SECONDARY_EXEC_TSC_SCALING) {
        mulu64(&low, &high, tsc, VMCS(TSC_MULTIPLIER));
        tsc = high << 16 | low >> 48;
    }
    return tsc + VMCS(TSC_OFFSET);
}

/*
 * How long a wait of DELAY ticks of the TSC that non-root operation reads
 * lasts on the processor's TSC: with "use TSC offsetting" and "use TSC
 * scaling", DELAY shifted left by 48 and divided by the TSC multiplier
 * (Intel SDM 325462-093 Vol. 3C, 28.3).
 */
uint64_t x86_vmx_tsc_delay(CPUX86State *env, uint64_t delay)
{
    uint64_t low = delay << 48, high = delay >> 16;

    if (!(VMCS(PROC_CONTROLS) & VMX_CPU_BASED_USE_TSC_OFFSETING) ||
        !(vmx_proc2(env) & VMX_SECONDARY_EXEC_TSC_SCALING)) {
        return delay;
    }
    divu128(&low, &high, VMCS(TSC_MULTIPLIER));
    return high ? UINT64_MAX : low;
}

/*
 * UMONITOR, UMWAIT, and TPAUSE run in non-root operation with "enable user
 * wait and pause" (Intel SDM 325462-093 Vol. 3C, 28.3).
 */
bool x86_vmx_user_wait_enabled(CPUX86State *env)
{
    return vmx_proc2(env) & VMX_SECONDARY_EXEC_ENABLE_USER_WAIT_PAUSE;
}

/*
 * With "RDTSC exiting" too, UMWAIT and TPAUSE exit, with their source
 * register in the instruction information (Intel SDM 325462-093 Vol. 3C,
 * 28.1.3 and Table 30-13).
 */
void x86_vmx_user_wait_exit(CPUX86State *env, uint32_t reason,
                            uint32_t info, uintptr_t ra)
{
    if (VMCS(PROC_CONTROLS) & VMX_CPU_BASED_RDTSC_EXITING) {
        VMCS_SET(EXIT_INSN_INFO, info);
        x86_vmx_exit(env, reason, 0, ra);
    }
}

/*
 * RDRAND and RDSEED exit with "RDRAND exiting" and "RDSEED exiting", their
 * register and operand size in the instruction information (Intel SDM
 * 325462-093 Vol. 3C, 28.1.3 and Table 30-12); bit 31 of INFO tells RDSEED.
 */
void x86_vmx_rdrand(CPUX86State *env, uint32_t info, uintptr_t ra)
{
    bool seed = info >> 31;

    if (vmx_proc2(env) & (seed ? VMX_SECONDARY_EXEC_RDSEED_EXITING :
                                 VMX_SECONDARY_EXEC_RDRAND_EXITING)) {
        VMCS_SET(EXIT_INSN_INFO, info & ~(1u << 31));
        x86_vmx_exit(env, seed ? VMX_EXIT_RDSEED : VMX_EXIT_RDRAND, 0, ra);
    }
}

/*
 * XSAVES and XRSTORS need "enable XSAVES/XRSTORS" in non-root operation,
 * and exit where EDX:EAX, IA32_XSS, and the XSS-exiting bitmap share a
 * bit (Intel SDM 325462-093 Vol. 3C, 28.1.3 and 28.3), with the memory
 * operand in the instruction information (Intel SDM 325462-093 Vol. 3C,
 * Table 30-14). #UD, #NM, and the #GP of CPL > 0 come before the exit
 * and the operand's faults after it: Intel SDM 325462-093 Vol. 3C, 28.1.1
 * has #UD go first but does not name #NM, which Intel SDM 325462-093 Vol.
 * 3A, Table 7-2 counts with #UD as a fault of decoding, and which an Intel
 * processor raised first. The XSAVES and XRSTORS helpers raise the faults
 * this one leaves.
 */
void HELPER(vmx_xsaves)(CPUX86State *env, uint32_t reason, uint32_t info,
                        target_ulong disp, uint64_t rfbm)
{
    if (!env->vmx.nonroot || !(env->cr[4] & CR4_OSXSAVE_MASK)) {
        return;
    }
    if (!(vmx_proc2(env) & VMX_SECONDARY_EXEC_XSAVES)) {
        raise_exception_ra(env, EXCP06_ILLOP, GETPC());
    }
    if (env->cr[0] & CR0_TS_MASK) {
        raise_exception_ra(env, EXCP07_PREX, GETPC());
    }
    if (!(env->hflags & HF_CPL_MASK) &&
        (rfbm & env->xss & VMCS(XSS_EXIT_BITMAP))) {
        VMCS_SET(EXIT_INSN_INFO, info);
        x86_vmx_exit(env, reason, disp, GETPC());
    }
}

/*
 * INVPCID needs "enable INVPCID" in non-root operation, and exits with
 * "INVLPG exiting" (Intel SDM 325462-093 Vol. 3C, 28.1.3 and 28.3).
 */
void x86_vmx_invpcid(CPUX86State *env, uintptr_t ra)
{
    if (!(vmx_proc2(env) & VMX_SECONDARY_EXEC_ENABLE_INVPCID)) {
        raise_exception_ra(env, EXCP06_ILLOP, ra);
    }
    if (VMCS(PROC_CONTROLS) & VMX_CPU_BASED_INVLPG_EXITING) {
        x86_vmx_exit(env, VMX_EXIT_INVPCID, 0, ra);
    }
}

/*
 * VMCALL: exits in non-root operation, fails in VMX root operation
 * without the dual-monitor treatment (Intel SDM 325462-093 Vol. 3C,
 * Chapter 33, VMCALL).
 */
void HELPER(vmcall)(CPUX86State *env)
{
    if (env->vmx.nonroot) {
        x86_vmx_exit(env, VMX_EXIT_VMCALL, 0, GETPC());
    }
    if (env->vmx.on && ((env->eflags & VM_MASK) ||
                        ((env->hflags & HF_LMA_MASK) &&
                         !(env->hflags & HF_CS64_MASK)))) {
        raise_exception_ra(env, EXCP06_ILLOP, GETPC());
    }
    vmx_check_root(env, GETPC());
    vmx_fail(env, VMXERR_VMCALL_ROOT);
}

/*
 * EPT (Intel SDM 325462-093 Vol. 3C, 31.3): guest-physical addresses
 * through the EPT paging structures EPTP names, 4 or 5 levels, with
 * 1 GiB and 2 MiB pages, execute-only translations, and accessed and
 * dirty flags where EPTP bit 6 enables them.
 */
#define VMCS_EPT_POINTER 0x201a
#define EPT_READ 1
#define EPT_WRITE 2
#define EPT_EXEC 4
#define EPT_LARGE (1ULL << 7)
#define EPT_EXEC_USER (1ULL << 10)
#define EPT_ACCESSED (1ULL << 8)
#define EPT_DIRTY (1ULL << 9)
#define EPTP_AD (1ULL << 6)
#define VMX_EXIT_EPT_VIOLATION 48
#define VMX_EXIT_EPT_MISCONFIG 49
#define VMX_EXIT_PML_FULL 62

bool x86_vmx_ept_active(CPUX86State *env)
{
    return env->vmx.nonroot &&
           (vmx_proc2(env) & VMX_SECONDARY_EXEC_ENABLE_EPT);
}

/*
 * Under the mode-based execute control, EPT allows fetches from user-mode and
 * from supervisor-mode linear addresses apart (Intel SDM 325462-093 Vol. 3C,
 * 31.3.3.2): the translations of supervisor-mode ones go through
 * MMU_NESTED_SUP_IDX.
 */
bool x86_vmx_ept_mbec(CPUX86State *env)
{
    return x86_vmx_ept_active(env) &&
           (vmx_proc2(env) & VMX_SECONDARY_EXEC_MODE_BASED_EPT_EXEC);
}

/*
 * Advanced VM-exit information of an EPT violation in the translation of a
 * linear address: whether paging makes its page user-mode, read/write, and
 * execute-disable, from FLAGS, the paging-structure entries' U/S, R/W, and
 * XD combined (Intel SDM 325462-093 Vol. 3C, Table 30-7).
 */
void x86_vmx_ept_guest_page(CPUX86State *env, uint64_t flags)
{
    uint64_t caps = env->features[FEAT_VMX_EPT_VPID_CAPS];

    if (x86_vmx_ept_active(env) && (caps & MSR_VMX_EPT_ADVANCED_VMEXIT_INFO)) {
        env->vmx.ept_qual |= (flags & PG_USER_MASK ? 1 << 9 : 0) |
                             (flags & PG_RW_MASK ? 1 << 10 : 0) |
                             (flags & PG_NX_MASK ? 1 << 11 : 0);
    }
}

/* Guest paging-structure accesses are writes where EPT has A/D flags. */
bool x86_vmx_ept_ad(CPUX86State *env)
{
    return VMCS(EPT_POINTER) & EPTP_AD;
}

/* An EPTP a VM entry accepts (Intel SDM 325462-093 Vol. 3C, 29.2.1.1). */
static bool vmx_eptp_valid(CPUX86State *env, uint64_t eptp)
{
    uint64_t caps = env->features[FEAT_VMX_EPT_VPID_CAPS];
    int type = eptp & 7, walk = ((eptp >> 3) & 7) + 1;

    /*
     * UC and WB, which IA32_VMX_EPT_VPID_CAP reports with EPT (Intel SDM
     * 325462-093 Vol. 3D, A.10).
     */
    if (type != 0 && type != 6) {
        return false;
    }
    if (!((walk == 4 && (caps & MSR_VMX_EPT_PAGE_WALK_LENGTH_4)) ||
          (walk == 5 && (caps & MSR_VMX_EPT_PAGE_WALK_LENGTH_5)))) {
        return false;
    }
    if (((eptp & EPTP_AD) && !(caps & MSR_VMX_EPT_AD_BITS)) ||
        (eptp & 0xf80) || (eptp >> env_archcpu(env)->phys_bits)) {
        return false;
    }
    return true;
}

/*
 * VMFUNC: #UD outside non-root operation, without "enable VM functions",
 * or for a function past 63, and an exit for a function the VM-function
 * controls leave off. EPTP switching, function 0 and the only one TCG has,
 * loads the EPTP-list entry ECX selects, exiting for an index past the
 * list, an EPTP a VM entry would refuse, or one of another page-walk
 * length; the PDPTEs stay as they are (Intel SDM 325462-093 Vol. 3C,
 * 28.5.7). The TLB, which holds one guest context, drops it.
 */
void HELPER(vmfunc)(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);
    uint32_t function = env->regs[R_EAX];
    uint32_t index = env->regs[R_ECX];
    uint64_t eptp;

    if (!env->vmx.nonroot ||
        !(vmx_proc2(env) & VMX_SECONDARY_EXEC_ENABLE_VMFUNC) ||
        function > 63) {
        raise_exception_ra(env, EXCP06_ILLOP, GETPC());
    }
    if (!(VMCS(VMFUNC_CONTROLS) >> function & 1) || index >= 512) {
        x86_vmx_exit(env, VMX_EXIT_VMFUNC, 0, GETPC());
    }
    eptp = x86_ldq_phys(cs, VMCS(EPTP_LIST_ADDR) + 8 * index);
    if (((eptp ^ VMCS(EPT_POINTER)) & (7 << 3)) ||
        !vmx_eptp_valid(env, eptp)) {
        x86_vmx_exit(env, VMX_EXIT_VMFUNC, 0, GETPC());
    }
    VMCS_SET(EPT_POINTER, eptp);
    env->vmx.tlb_eptp = eptp;
    tlb_flush_by_mmuidx(cs, MMU_GUEST_IDX_MAP | 1 << MMU_NESTED_IDX |
                            1 << MMU_NESTED_SUP_IDX);
}

static bool ept_set_flags(CPUX86State *env, hwaddr addr, uint64_t old,
                          uint64_t new)
{
    CPUState *cs = env_cpu(env);
    hwaddr len = 8;
    uint64_t *p = address_space_map(cs->as, addr, &len, true,
                                    MEMTXATTRS_UNSPECIFIED);
    bool done;

    if (!p || len < 8) {
        if (p) {
            address_space_unmap(cs->as, p, len, false, 0);
        }
        x86_stq_phys(cs, addr, new);
        return true;
    }
    done = qatomic_cmpxchg__nocheck(p, cpu_to_le64(old), cpu_to_le64(new)) ==
           cpu_to_le64(old);
    address_space_unmap(cs->as, p, len, true, 8);
    return done;
}

/*
 * Page-modification logging: a dirty flag an EPT walk sets logs the 4-KByte
 * page of the guest-physical address at the PML index, which then counts down
 * (Intel SDM 325462-093 Vol. 3C, 31.3.6).
 */
static void ept_pml_log(CPUX86State *env, hwaddr gpa)
{
    uint64_t index = VMCS(PML_INDEX);

    x86_stq_phys(env_cpu(env), VMCS(PML_ADDR) + 8 * index, gpa & ~0xfffULL);
    VMCS_SET(PML_INDEX, (index - 1) & 0xffff);
}

/*
 * One translation: the host-physical address, protections, and page size, or
 * false with the EPT violation's qualification, or a misconfiguration, kept for
 * the exit (Intel SDM 325462-093 Vol. 3C, 31.3.3). Stores include, with A/D
 * flags, the guest's paging-structure accesses. Under page-modification
 * logging, a flag to set with the PML index past 511 makes a log-full event
 * instead, setting nothing (Intel SDM 325462-093 Vol. 3C, 31.3.6). Under the
 * mode-based execute control, bit 10 makes an entry present too, and allows
 * the fetches bit 2 then leaves to supervisor-mode linear addresses, those
 * from user-mode ones, a fetch being SUPERVISOR's or not (Intel SDM
 * 325462-093 Vol. 3C, 31.3.2 and 31.3.3.2).
 */
bool x86_vmx_ept_translate(CPUX86State *env, hwaddr gpa,
                           MMUAccessType access, bool supervisor,
                           hwaddr *hpa, int *prot, int *page_size)
{
    CPUState *cs = env_cpu(env);
    uint64_t eptp = VMCS(EPT_POINTER);
    uint64_t caps = env->features[FEAT_VMX_EPT_VPID_CAPS];
    uint64_t addr_mask = PG_ADDRESS_MASK &
                         MAKE_64BIT_MASK(0, env_archcpu(env)->phys_bits);
    bool ad = eptp & EPTP_AD;
    bool pml = ad && (vmx_proc2(env) & VMX_SECONDARY_EXEC_ENABLE_PML);
    bool mbec = vmx_proc2(env) & VMX_SECONDARY_EXEC_MODE_BASED_EPT_EXEC;
    int levels = ((eptp >> 3) & 7) + 1;
    hwaddr table = eptp & addr_mask;
    uint64_t present = mbec ? 7 | EPT_EXEC_USER : 7;
    uint64_t exec = mbec && !supervisor ? EPT_EXEC_USER : EPT_EXEC;
    uint64_t perms = present;
    uint64_t need, entry = 0;
    hwaddr entry_addr = 0;
    int level, shift = 12;

    env->vmx.ept_misconfig = false;
    env->vmx.pml_full = false;
    need = access == MMU_DATA_STORE ? EPT_WRITE :
           access == MMU_INST_FETCH ? exec : EPT_READ;
    for (level = levels; level >= 1; level--) {
        bool large;

        shift = 12 + 9 * (level - 1);
        entry_addr = table + ((gpa >> shift) & 0x1ff) * 8;
    again:
        entry = x86_ldq_phys(cs, entry_addr);
        if (!(entry & present)) {
            goto violation;
        }
        large = (entry & EPT_LARGE) && level <= 3 && level >= 2;
        if ((entry & 3) == EPT_WRITE ||
            (!(entry & 3) && !(caps & MSR_VMX_EPT_EXECONLY)) ||
            (entry & ~addr_mask & MAKE_64BIT_MASK(12, 40)) ||
            (level >= 4 && (entry & 0xf8)) ||
            (level == 3 && large && !(caps & MSR_VMX_EPT_1GB)) ||
            (level == 2 && large && !(caps & MSR_VMX_EPT_2MB)) ||
            (!large && level > 1 && (entry & 0x78))) {
            goto misconfig;
        }
        if (large || level == 1) {
            int type = (entry >> 3) & 7;

            if (type == 2 || type == 3 || type == 7 ||
                (large && (entry & MAKE_64BIT_MASK(12, shift - 12)))) {
                goto misconfig;
            }
        }
        perms &= entry & present;
        if (ad && !(entry & EPT_ACCESSED)) {
            if (pml && VMCS(PML_INDEX) > 511) {
                goto pml_full;
            }
            if (!ept_set_flags(env, entry_addr, entry, entry | EPT_ACCESSED)) {
                goto again;
            }
            entry |= EPT_ACCESSED;
        }
        if (large || level == 1) {
            break;
        }
        table = entry & addr_mask;
    }
    if (!(perms & need)) {
        goto violation;
    }
    if (ad && need == EPT_WRITE && !(entry & EPT_DIRTY)) {
        if (pml && VMCS(PML_INDEX) > 511) {
            goto pml_full;
        }
        if (!ept_set_flags(env, entry_addr, entry, entry | EPT_DIRTY)) {
            return x86_vmx_ept_translate(env, gpa, access, supervisor, hpa,
                                         prot, page_size);
        }
        entry |= EPT_DIRTY;
        if (pml) {
            ept_pml_log(env, gpa);
        }
    }
    *page_size = 1 << shift;
    *hpa = (entry & addr_mask & ~(uint64_t)(*page_size - 1)) |
           (gpa & (*page_size - 1));
    *prot = (perms & EPT_READ ? PAGE_READ : 0) |
            (perms & exec ? PAGE_EXEC : 0);
    /* Writes wait for the dirty flag where EPT keeps one. */
    if ((perms & EPT_WRITE) && (!ad || (entry & EPT_DIRTY))) {
        *prot |= PAGE_WRITE;
    }
    return true;

violation:
    env->vmx.ept_qual = access == MMU_DATA_STORE ? 2 :
                        access == MMU_INST_FETCH ? 4 : 1;
    if (level < 1 || (entry & present)) {
        env->vmx.ept_qual |= (perms & entry & 7) << 3 |
                             (perms & entry & EPT_EXEC_USER ? 1 << 6 : 0);
    }
    return false;
misconfig:
    env->vmx.ept_misconfig = true;
    return false;
pml_full:
    env->vmx.pml_full = true;
    return false;
}

/*
 * The exit of an EPT violation or misconfiguration, or of a page-modification
 * log-full event: the guest-physical address, and for a violation the linear
 * address, which final is whether the access was to (rather than for
 * translating) (Intel SDM 325462-093 Vol. 3C, Table 30-7).
 * A write to a guest paging structure, which all accesses to them are with EPT
 * A/D (Intel SDM 325462-093 Vol. 3C, Table 30-7, note 1) and flag updates are
 * without, also reads.
 */
G_NORETURN void x86_vmx_ept_exit(CPUX86State *env, hwaddr gpa,
                                 target_ulong linear, bool final,
                                 uintptr_t ra)
{
    uint64_t qual = env->vmx.ept_qual | 1 << 7 | (final ? 1 << 8 : 0);

    VMCS_SET(GUEST_PHYS_ADDR, gpa);
    if (env->vmx.ept_misconfig) {
        x86_vmx_exit(env, VMX_EXIT_EPT_MISCONFIG, 0, ra);
    }
    if (env->vmx.pml_full) {
        x86_vmx_exit(env, VMX_EXIT_PML_FULL, 0, ra);
    }
    if (!final && (qual & 2)) {
        qual |= 1;
    }
    VMCS_SET(GUEST_LINEAR_ADDR, linear);
    x86_vmx_exit(env, VMX_EXIT_EPT_VIOLATION, qual, ra);
}
