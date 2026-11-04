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
#include "qemu/log.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cputlb.h"
#include "accel/tcg/cpu-ldst.h"
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
#define VMXERR_VMCLEAR_ADDR 2
#define VMXERR_VMCLEAR_VMXON 3
#define VMXERR_VMPTRLD_ADDR 9
#define VMXERR_VMPTRLD_VMXON 10
#define VMXERR_VMPTRLD_REVISION 11
#define VMXERR_FIELD 12
#define VMXERR_READ_ONLY 13
#define VMXERR_VMXON_ROOT 15

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
 * VMREAD of a field of the VMCS fields: the high access type of a 64-bit
 * field reads its bits 63:32; narrower fields read zero-extended.
 */
static bool vmcs_get(const uint64_t *vmcs, uint64_t encoding, uint64_t *val)
{
    unsigned width = VMCS_ENC_WIDTH(encoding);
    bool high = encoding & VMCS_ENC_HIGH;
    int slot;

    if (encoding >> 15 || (high && width != VMCS_WIDTH_64)) {
        return false;
    }
    slot = vmcs_slot(encoding & ~VMCS_ENC_HIGH);
    if (slot < 0) {
        return false;
    }
    *val = vmcs[slot];
    if (high) {
        *val >>= 32;
    } else if (width == VMCS_WIDTH_16) {
        *val &= 0xffff;
    } else if (width == VMCS_WIDTH_32) {
        *val &= 0xffffffff;
    }
    return true;
}

/*
 * VMWRITE: the high access type writes bits 63:32 only; a field longer than
 * the value gets its high bits cleared. Access rights keep their defined
 * bits, as Linux 7.3's KVM does with them.
 */
static void vmcs_set(uint64_t *vmcs, int slot, uint64_t encoding,
                     uint64_t val)
{
    unsigned width = VMCS_ENC_WIDTH(encoding);

    if (encoding & VMCS_ENC_HIGH) {
        vmcs[slot] = (uint32_t)vmcs[slot] | (uint64_t)(uint32_t)val << 32;
        return;
    }
    if (width == VMCS_WIDTH_16) {
        val &= 0xffff;
    } else if (width == VMCS_WIDTH_32) {
        val &= 0xffffffff;
    }
    if (encoding >= 0x4814 && encoding <= 0x4822) {
        val &= 0x1f0ff;
    }
    vmcs[slot] = val;
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

bool x86_vmx_cr_valid(CPUX86State *env, int cr, uint64_t val)
{
    uint64_t fixed0 = vmx_cr_fixed0(cr);

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
 * destination keeps its old value where VMREAD fails.
 */
static bool vmx_check_vmread(CPUX86State *env, target_ulong field,
                             uint64_t *val, uintptr_t ra)
{
    vmx_check_root(env, ra);
    if (env->vmx.vmcs_ptr == ~0ULL) {
        vmx_fail_invalid(env);
        return false;
    }
    if (!vmcs_get(env->vmx.vmcs, field, val)) {
        vmx_fail(env, VMXERR_FIELD);
        return false;
    }
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
    uint64_t old;
    int slot;

    if (!vmcs_get(env->vmx.vmcs, field, &old)) {
        vmx_fail(env, VMXERR_FIELD);
        return;
    }
    if (VMCS_ENC_TYPE(field) == VMCS_TYPE_EXIT_INFO &&
        !(env->features[FEAT_VMX_MISC] & MSR_VMX_MISC_VMWRITE_VMEXIT)) {
        vmx_fail(env, VMXERR_READ_ONLY);
        return;
    }
    slot = vmcs_slot(field & ~VMCS_ENC_HIGH);
    vmcs_set(env->vmx.vmcs, slot, field, val);
    vmx_succeed(env);
}

void HELPER(vmwrite)(CPUX86State *env, target_ulong field, target_ulong val)
{
    vmx_check_root(env, GETPC());
    if (env->vmx.vmcs_ptr == ~0ULL) {
        vmx_fail_invalid(env);
        return;
    }
    vmx_vmwrite(env, field, val);
}

void HELPER(vmwrite_mem)(CPUX86State *env, target_ulong field,
                        target_ulong ptr, int seg)
{
    uintptr_t ra = GETPC();
    uint64_t val;

    vmx_check_root(env, ra);
    if (env->vmx.vmcs_ptr == ~0ULL) {
        vmx_fail_invalid(env);
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
 * 26.8): it waits for VMXOFF.
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
