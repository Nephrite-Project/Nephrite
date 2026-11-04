/*
 *  x86 misc helpers
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/host-utils.h"
#include "qemu/log.h"
#include "accel/tcg/cpu-loop.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cputlb.h"
#include "helper-tcg.h"

/*
 * NOTE: the translator must set DisasContext.cc_op to CC_OP_EFLAGS
 * after generating a call to a helper that uses this.
 */
void cpu_load_eflags(CPUX86State *env, int eflags, int update_mask)
{
    CC_SRC = eflags & (CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
    CC_OP = CC_OP_EFLAGS;
    env->df = 1 - (2 * ((eflags >> 10) & 1));
    env->eflags = (env->eflags & ~update_mask) |
        (eflags & update_mask) | 0x2;
}

void HELPER(into)(CPUX86State *env, int next_eip_addend)
{
    int eflags;

    eflags = cpu_cc_compute_all(env);
    if (eflags & CC_O) {
        raise_trap_instruction(env, EXCP04_INTO, next_eip_addend);
    }
}

void HELPER(cpuid)(CPUX86State *env)
{
    uint32_t eax, ebx, ecx, edx;

    /*
     * CPUID faulting: IA32_MISC_FEATURES_ENABLES bit 0 (Intel) or
     * HWCR.CpuidUserDis (AMD) makes CPUID at CPL > 0 outside SMM raise
     * #GP(0), before any intercept (AMD64 Architecture Programmer's Manual
     * Volume 3, 24594 rev. 3.38, CPUID; Intel SDM 325462-093 Vol. 3C,
     * 28.1.1).
     */
    if ((env->hflags & HF_CPL_MASK) && !(env->hflags & HF_SMM_MASK) &&
        ((env->msr_misc_features_enables & MISC_FEATURES_CPUID_FAULT) ||
         (env->msr_hwcr & HWCR_CPUID_USER_DIS))) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }

    cpu_svm_check_intercept_param(env, SVM_EXIT_CPUID, 0, GETPC());

    cpu_x86_cpuid(env, (uint32_t)env->regs[R_EAX], (uint32_t)env->regs[R_ECX],
                  &eax, &ebx, &ecx, &edx);
#ifndef CONFIG_USER_ONLY
    x86_amd_cpuid_hide(env, (uint32_t)env->regs[R_EAX],
                       (uint32_t)env->regs[R_ECX], &eax, &ebx, &ecx, &edx);
#endif
    env->regs[R_EAX] = eax;
    env->regs[R_EBX] = ebx;
    env->regs[R_ECX] = ecx;
    env->regs[R_EDX] = edx;
}

/*
 * The TSC as software reads it: the clock, moved by what IA32_TSC was set
 * to, which SVM guest mode reads scaled by the TSC ratio, an 8.32 fixed
 * point number, plus the VMCB's TSC offset.
 */
uint64_t x86_tsc_read(CPUX86State *env)
{
    uint64_t tsc = cpu_get_tsc(env) + env->tsc_written_delta;
    uint64_t low, high;

    if (!(env->hflags & HF_GUEST_MASK)) {
        return tsc;
    }
#if !defined(CONFIG_USER_ONLY)
    if (env->vmx.nonroot) {
        return x86_vmx_tsc(env, tsc);
    }
#endif
    mulu64(&low, &high, tsc, env->amd_tsc_scale_msr);
    return ((high << 32) | (low >> 32)) + env->tsc_offset;
}

static void do_rdtsc(CPUX86State *env, uint32_t intercept, uintptr_t retaddr)
{
    uint64_t val;

    if ((env->cr[4] & CR4_TSD_MASK) && ((env->hflags & HF_CPL_MASK) != 0)) {
        raise_exception_ra(env, EXCP0D_GPF, retaddr);
    }
    cpu_svm_check_intercept_param(env, intercept, 0, retaddr);

    val = x86_tsc_read(env);
    env->regs[R_EAX] = (uint32_t)(val);
    env->regs[R_EDX] = (uint32_t)(val >> 32);
#if !defined(CONFIG_USER_ONLY)
    x86_vmx_tsc_seen(env);
#endif
}

void HELPER(rdtsc)(CPUX86State *env)
{
    do_rdtsc(env, SVM_EXIT_RDTSC, GETPC());
}

/* RDTSCP has an intercept of its own. */
void HELPER(rdtscp)(CPUX86State *env)
{
#if !defined(CONFIG_USER_ONLY)
    if (env->vmx.nonroot && !x86_vmx_rdtscp_allowed(env)) {
        raise_exception_ra(env, EXCP06_ILLOP, GETPC());
    }
#endif
    do_rdtsc(env, SVM_EXIT_RDTSCP, GETPC());
}

void HELPER(rdpmc)(CPUX86State *env)
{
    if (((env->cr[4] & CR4_PCE_MASK) == 0 ) &&
        ((env->hflags & HF_CPL_MASK) != 0)) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }
    cpu_svm_check_intercept_param(env, SVM_EXIT_RDPMC, 0, GETPC());

#ifndef CONFIG_USER_ONLY
    if (x86_pmu_rdpmc(env)) {
        return;
    }
#endif
    /* A counter that does not exist (Intel SDM 325462-093 Vol. 2B, RDPMC). */
    raise_exception_ra(env, EXCP0D_GPF, GETPC());
}

G_NORETURN void HELPER(pause)(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);

    /* Do gen_eob() tasks before going back to the main loop.  */
    do_end_instruction(env);
    HELPER(rechecking_single_step)(env);

    /* Just let another CPU run.  */
    cs->exception_index = EXCP_INTERRUPT;
    cpu_loop_exit(cs);
}

uint64_t HELPER(rdpkru)(CPUX86State *env, uint32_t ecx)
{
    if ((env->cr[4] & CR4_PKE_MASK) == 0) {
        raise_exception_err_ra(env, EXCP06_ILLOP, 0, GETPC());
    }
    if (ecx != 0) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }

    return env->pkru;
}

void HELPER(wrpkru)(CPUX86State *env, uint32_t ecx, uint64_t val)
{
    CPUState *cs = env_cpu(env);

    if ((env->cr[4] & CR4_PKE_MASK) == 0) {
        raise_exception_err_ra(env, EXCP06_ILLOP, 0, GETPC());
    }
    if (ecx != 0 || (val & 0xFFFFFFFF00000000ull)) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }

    env->pkru = val;
    tlb_flush(cs);
}

target_ulong HELPER(rdpid)(CPUX86State *env)
{
#if !defined CONFIG_USER_ONLY
    if (env->vmx.nonroot && !x86_vmx_rdtscp_allowed(env)) {
        raise_exception_ra(env, EXCP06_ILLOP, GETPC());
    }
    return env->tsc_aux;
#elif defined CONFIG_LINUX && defined CONFIG_GETCPU
    unsigned cpu, node;
    getcpu(&cpu, &node);
    return (node << 12) | (cpu & 0xfff);
#elif defined CONFIG_SCHED_GETCPU
    return sched_getcpu();
#else
    return 0;
#endif
}
