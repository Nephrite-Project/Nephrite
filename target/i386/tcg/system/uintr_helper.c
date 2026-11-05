/*
 * x86 user interrupts for TCG (system emulator)
 *
 * User interrupts (Intel SDM 325462-093 Vol. 3A, chapter 9): their MSRs,
 * delivery at CPL 3, user-interrupt notification identification and
 * processing, and UIRET, CLUI, STUI, TESTUI, and SENDUIPI (Vol. 2A and
 * 2B). The memory accesses to UPIDs and UITT entries are supervisor ones,
 * and those of delivery and UIRET are at the CPL, 3 for delivery.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "accel/tcg/cpu-ldst.h"
#include "accel/tcg/cpu-loop.h"
#include "hw/i386/apic.h"
#include "tcg/helper-tcg.h"
#include "../seg_helper.h"
#include "../tcg-cpu.h"

/* IA32_UINTR_MISC: UITTSZ in bits 31:0, UINV in bits 39:32. */
#define UINTR_MISC_UINV_SHIFT   32
#define UINTR_MISC_RESERVED     (~0ULL << 40)
#define UINTR_PD_RESERVED       0x3fULL
#define UINTR_TT_SENDUIPI       1ULL
#define UINTR_TT_RESERVED       0xeULL

/* The bits RFLAGS takes from the image that UIRET pops. */
#define UIRET_RFLAGS_MASK       (CC_C | CC_P | CC_A | CC_Z | CC_S | TF_MASK | \
                                 DF_MASK | CC_O | NT_MASK | RF_MASK | \
                                 AC_MASK | ID_MASK)

/* UPID: ON, SN, the notification vector in 23:16, NDST in 63:32. */
#define UPID_ON                 1ULL
#define UPID_SN                 2ULL
#define UPID_RESERVED           0xff00fffcULL

/* UITT entry: V, the vector in bits 13:8, the UPID's address above. */
#define UITTE_V                 1ULL
#define UITTE_RESERVED          (~0x3f01ULL)

uint8_t x86_uintr_uinv(CPUX86State *env)
{
    return env->uintr_misc >> UINTR_MISC_UINV_SHIFT;
}

void x86_uintr_set_uinv(CPUX86State *env, uint8_t uinv)
{
    env->uintr_misc = (env->uintr_misc & ~(0xffULL << UINTR_MISC_UINV_SHIFT)) |
                      (uint64_t)uinv << UINTR_MISC_UINV_SHIFT;
}

/*
 * A pending user interrupt is recognized whenever UIRR is not 0 (Intel SDM
 * 325462-093 Vol. 3A, 9.4.1), after whatever changed UIRR. Only this
 * processor changes its UIRR, between instructions or at the end of a TB;
 * one it can deliver at once stops chained TBs, which would run past it.
 */
void x86_uintr_recognize(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);

    if (env->uintr_rr) {
        cpu_set_interrupt(cs, CPU_INTERRUPT_UINTR);
        if (x86_uintr_deliverable(env)) {
            qatomic_set(&cs->neg.icount_decr.u16.high, -1);
        }
    } else {
        cpu_reset_interrupt(cs, CPU_INTERRUPT_UINTR);
    }
}

/*
 * Whether the value of an XSAVE image or a WRMSR fits the user-interrupt
 * MSR msr: canonical linear addresses, for the processor's maximum
 * linear-address width, and no reserved bit (Intel SDM 325462-093 Vol. 3A,
 * 9.3.2).
 */
bool x86_uintr_msr_valid(CPUX86State *env, uint32_t msr, uint64_t val)
{
    switch (msr) {
    case MSR_IA32_UINTR_HANDLER:
    case MSR_IA32_UINTR_STACKADJUST:
        return x86_canonical(env, val, false);
    case MSR_IA32_UINTR_MISC:
        return !(val & UINTR_MISC_RESERVED);
    case MSR_IA32_UINTR_PD:
        return !(val & UINTR_PD_RESERVED) && x86_canonical(env, val, false);
    case MSR_IA32_UINTR_TT:
        return !(val & UINTR_TT_RESERVED) &&
               x86_canonical(env, val & ~0xfULL, false);
    default:
        return true;
    }
}

/* RDMSR of a user-interrupt MSR: -1 for other MSRs, 0 for #GP. */
int x86_uintr_rdmsr(CPUX86State *env, uint32_t msr, uint64_t *val)
{
    if (msr < MSR_IA32_UINTR_RR || msr > MSR_IA32_UINTR_TT) {
        return -1;
    }
    if (!(env->features[FEAT_7_0_EDX] & CPUID_7_0_EDX_UINTR)) {
        return 0;
    }
    switch (msr) {
    case MSR_IA32_UINTR_RR:
        *val = env->uintr_rr;
        break;
    case MSR_IA32_UINTR_HANDLER:
        *val = env->uintr_handler;
        break;
    case MSR_IA32_UINTR_STACKADJUST:
        *val = env->uintr_stackadjust;
        break;
    case MSR_IA32_UINTR_MISC:
        *val = env->uintr_misc;
        break;
    case MSR_IA32_UINTR_PD:
        *val = env->uintr_pd;
        break;
    default:
        *val = env->uintr_tt;
        break;
    }
    return 1;
}

/* WRMSR of a user-interrupt MSR: -1 for other MSRs, 0 for #GP. */
int x86_uintr_wrmsr(CPUX86State *env, uint32_t msr, uint64_t val)
{
    if (msr < MSR_IA32_UINTR_RR || msr > MSR_IA32_UINTR_TT) {
        return -1;
    }
    if (!(env->features[FEAT_7_0_EDX] & CPUID_7_0_EDX_UINTR) ||
        !x86_uintr_msr_valid(env, msr, val)) {
        return 0;
    }
    switch (msr) {
    case MSR_IA32_UINTR_RR:
        env->uintr_rr = val;
        x86_uintr_recognize(env);
        break;
    case MSR_IA32_UINTR_HANDLER:
        env->uintr_handler = val;
        break;
    case MSR_IA32_UINTR_STACKADJUST:
        env->uintr_stackadjust = val;
        break;
    case MSR_IA32_UINTR_MISC:
        env->uintr_misc = val;
        break;
    case MSR_IA32_UINTR_PD:
        env->uintr_pd = val;
        break;
    default:
        env->uintr_tt = val;
        break;
    }
    return 1;
}

/*
 * User-interrupt delivery (Intel SDM 325462-093 Vol. 3A, 9.4.2), once
 * x86_uintr_deliverable(): to UIHANDLER, on the stack that UISTACKADJUST
 * gives, aligned to 16 bytes, with the old RSP, RFLAGS, RIP, and the
 * vector pushed, the return address also on the shadow stack, the
 * indirect branch tracker waiting for an ENDBRANCH, and the last branch
 * records taking it as they take ordinary interrupts. A fault leaves RSP,
 * UIRR, and UIF as they were, with EXT clear in its error code.
 */
void x86_uintr_deliver(CPUX86State *env)
{
    int mmu_idx = x86_mmu_index_pl(env, 3);
    int vector = 63 - clz64(env->uintr_rr);
    uint64_t rsp = env->regs[R_ESP];
    target_ulong from = env->eip;
    uint64_t sp;

    if (!x86_canonical(env, env->uintr_handler, true)) {
        raise_exception_err(env, EXCP0D_GPF, 0);
    }
    sp = env->uintr_stackadjust & 1 ? env->uintr_stackadjust :
         rsp - env->uintr_stackadjust;
    sp &= ~0xfULL;
    if (!x86_canonical(env, sp - 32, true) ||
        !x86_canonical(env, sp - 1, true)) {
        raise_exception_err(env, EXCP0C_STACK, 0);
    }
    cpu_stq_le_mmuidx_ra(env, sp - 8, rsp, mmu_idx, 0);
    cpu_stq_le_mmuidx_ra(env, sp - 16, cpu_compute_eflags(env), mmu_idx, 0);
    cpu_stq_le_mmuidx_ra(env, sp - 24, env->eip, mmu_idx, 0);
    cpu_stq_le_mmuidx_ra(env, sp - 32, vector, mmu_idx, 0);
    if (x86_shstk_enabled(env, 3)) {
        x86_shstk_push(env, env->eip, 0);
    }
    x86_ibt_far(env, 3);

    env->uif = false;
    env->uintr_rr &= ~(1ULL << vector);
    x86_uintr_recognize(env);
    env->eflags &= ~(TF_MASK | RF_MASK);
    env->regs[R_ESP] = sp - 32;
    env->eip = env->uintr_handler;
    if (env->debugctl & DEBUGCTL_LBR) {
        env->lbr_int_from = env->lbr_from;
        env->lbr_int_to = env->lbr_to;
        env->lbr_from = from;
        env->lbr_to = env->eip;
    }
}

/*
 * User-interrupt notification processing (Intel SDM 325462-093 Vol. 3A,
 * 9.5.2), with the UPID at IA32_UINTR_PD: the outstanding-notification
 * bit clears and PIR moves to UIRR, each atomically, as other processors
 * post. A fault's error code has EXT set.
 */
void x86_uintr_process(CPUX86State *env)
{
    MemOpIdx oi = make_memop_idx(MO_LEUQ, cpu_mmu_index_kernel(env));
    uint64_t upid = env->uintr_pd;
    uint64_t pir;

    if (!x86_canonical(env, upid, true)) {
        raise_exception_err(env, EXCP0D_GPF, 1);
    }
    cpu_atomic_fetch_andq_le_mmu(env, upid, ~UPID_ON, oi, 0);
    pir = cpu_atomic_xchgq_le_mmu(env, upid + 8, 0, oi, 0);
    if (pir) {
        env->uintr_rr |= pir;
        x86_uintr_recognize(env);
    }
}

/*
 * User-interrupt notification identification (Intel SDM 325462-093 Vol.
 * 3A, 9.5.1), for the ordinary interrupt the local APIC gave as vector:
 * with CR4.UINTR and IA32_EFER.LMA set, the vector UINV is a notification,
 * which the APIC takes an EOI for and processing follows, instead of
 * delivery through the IDT. Returns whether it was one.
 */
bool x86_uintr_notification(CPUX86State *env, int vector)
{
    if (!(env->cr[4] & CR4_UINTR_MASK) || !(env->hflags & HF_LMA_MASK) ||
        vector != x86_uintr_uinv(env)) {
        return false;
    }
    apic_write_eoi(env_archcpu(env)->apic_state);
    x86_uintr_process(env);
    return true;
}

static void uintr_check(CPUX86State *env, uintptr_t ra)
{
    if (!(env->cr[4] & CR4_UINTR_MASK)) {
        raise_exception_ra(env, EXCP06_ILLOP, ra);
    }
}

void HELPER(clui)(CPUX86State *env)
{
    uintr_check(env, GETPC());
    env->uif = false;
}

void HELPER(stui)(CPUX86State *env)
{
    uintr_check(env, GETPC());
    env->uif = true;
}

target_ulong HELPER(testui)(CPUX86State *env)
{
    uintr_check(env, GETPC());
    return env->uif;
}

/*
 * UIRET (Intel SDM 325462-093 Vol. 2B): pops RIP, RFLAGS, and RSP, checks
 * RIP against the shadow stack's, takes some of the RFLAGS bits, sets UIF,
 * or with UIRET_UIF loads it from bit 1 of the RFLAGS image, and ends
 * address-range monitoring.
 */
void HELPER(uiret)(CPUX86State *env)
{
    uintptr_t ra = GETPC();
    int mmu_idx = cpu_mmu_index(env_cpu(env), false);
    uint64_t sp = env->regs[R_ESP];
    uint64_t rip, rflags, rsp;

    uintr_check(env, ra);
    if (!x86_canonical(env, sp, true) || !x86_canonical(env, sp + 23, true)) {
        raise_exception_err_ra(env, EXCP0C_STACK, 0, ra);
    }
    rip = cpu_ldq_le_mmuidx_ra(env, sp, mmu_idx, ra);
    rflags = cpu_ldq_le_mmuidx_ra(env, sp + 8, mmu_idx, ra);
    rsp = cpu_ldq_le_mmuidx_ra(env, sp + 16, mmu_idx, ra);
    if (!x86_canonical(env, rip, true)) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }
    if (x86_shstk_enabled(env, env->hflags & HF_CPL_MASK)) {
        x86_shstk_pop_check(env, rip, CP_FAR_RET_IRET, ra);
    }
    env->eip = rip;
    cpu_load_eflags(env, rflags, UIRET_RFLAGS_MASK);
    env->regs[R_ESP] = rsp;
    env->uif = !(env->features[FEAT_7_1_EDX] & CPUID_7_1_EDX_UIRET_UIF) ||
               (rflags & 2);
    env->monitor_armed = false;
    env->umonitor_armed = false;
}

/*
 * SENDUIPI (Intel SDM 325462-093 Vol. 2B; Vol. 3A, 9.8): posts the user
 * interrupt of the UITT entry that index selects in the UPID the entry
 * names, then, where neither ON nor SN was set, sets ON and sends the
 * UPID's notification.
 */
void HELPER(senduipi)(CPUX86State *env, target_ulong index)
{
    uintptr_t ra = GETPC();
    int mmu_idx = cpu_mmu_index_kernel(env);
    MemOpIdx oi = make_memop_idx(MO_LEUQ, mmu_idx);
    uint64_t uitte, upid, old, new;
    int vector;

    uintr_check(env, ra);
    if (!(env->uintr_tt & UINTR_TT_SENDUIPI)) {
        raise_exception_ra(env, EXCP06_ILLOP, ra);
    }
    if (index > (uint32_t)env->uintr_misc) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }
    uitte = (env->uintr_tt & ~0xfULL) + (index << 4);
    if (!x86_canonical(env, uitte, true) ||
        !x86_canonical(env, uitte + 15, true)) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }
    old = cpu_ldq_le_mmuidx_ra(env, uitte, mmu_idx, ra);
    upid = cpu_ldq_le_mmuidx_ra(env, uitte + 8, mmu_idx, ra);
    if (!(old & UITTE_V) || (old & UITTE_RESERVED) || (upid & 0x3f) ||
        !x86_canonical(env, upid, true)) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }
    vector = old >> 8 & 0x3f;

    /*
     * Posted as agents post (Intel SDM 325462-093 Vol. 3C, 32.1.6.1): the
     * request first, then ON, the notification for whoever set it.
     */
    old = cpu_ldq_le_mmuidx_ra(env, upid, mmu_idx, ra);
    if (old & UPID_RESERVED) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }
    cpu_atomic_fetch_orq_le_mmu(env, upid + 8, 1ULL << vector, oi, ra);
    while (!(old & (UPID_ON | UPID_SN))) {
        new = cpu_atomic_cmpxchgq_le_mmu(env, upid, old, old | UPID_ON, oi,
                                         ra);
        if (new == old) {
            BQL_LOCK_GUARD();
            apic_send_user_ipi(env_archcpu(env)->apic_state, old >> 32,
                               old >> 16);
            break;
        }
        old = new;
    }
}
