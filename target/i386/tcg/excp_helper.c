/*
 *  x86 exception helpers
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
#include "accel/tcg/cpu-loop.h"
#include "cpu.h"
#include "qemu/log.h"
#include "system/runstate.h"
#include "exec/helper-proto.h"
#include "helper-tcg.h"
#include "qemu/plugin.h"

G_NORETURN void HELPER(raise_interrupt)(CPUX86State *env, int intno,
                                          int next_eip_addend)
{
    raise_interrupt(env, intno, next_eip_addend);
}

G_NORETURN void HELPER(int3)(CPUX86State *env, int next_eip_addend)
{
    raise_trap_instruction(env, EXCP03_INT3, next_eip_addend);
}

G_NORETURN void HELPER(raise_exception)(CPUX86State *env, int exception_index)
{
    raise_exception(env, exception_index);
}

G_NORETURN void HELPER(raise_gpf)(CPUX86State *env)
{
    raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
}

/*
 * Check nested exceptions and change to double or triple fault if
 * needed. It should only be called, if this is not an interrupt.
 * Returns the new exception number.
 */
static int check_exception(CPUX86State *env, int intno, int *error_code,
                           uintptr_t retaddr)
{
    /*
     * The contributory exceptions: #DE, #TS, #NP, #SS, #GP, and #CP (Intel
     * SDM 325462-093 Vol. 3A, Table 7-4).
     */
    int first_contributory = env->old_exception == 0 ||
                              (env->old_exception >= 10 &&
                               env->old_exception <= 13) ||
                              env->old_exception == EXCP15_CP;
    int second_contributory = intno == 0 ||
                               (intno >= 10 && intno <= 13) ||
                               intno == EXCP15_CP;

    qemu_log_mask(CPU_LOG_INT, "check_exception old: 0x%x (%s) new 0x%x (%s)\n",
                env->old_exception,
                env->old_exception == -1 ? "none"
                    : x86_exception_name(env->old_exception),
                intno, x86_exception_name(intno));

#if !defined(CONFIG_USER_ONLY)
    if (env->old_exception == EXCP08_DBLE) {
        if (env->vmx.nonroot) {
            x86_vmx_check_intercept(env, SVM_EXIT_SHUTDOWN, 0, retaddr);
        }
        if (env->hflags & HF_GUEST_MASK) {
            cpu_vmexit(env, SVM_EXIT_SHUTDOWN, 0, retaddr); /* does not return */
        }

        qemu_log_mask(CPU_LOG_RESET, "Triple fault\n");

        qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
        return EXCP_HLT;
    }
#endif

    if ((first_contributory && second_contributory)
        || (env->old_exception == EXCP0E_PAGE &&
            (second_contributory || (intno == EXCP0E_PAGE)))) {
        intno = EXCP08_DBLE;
        *error_code = 0;
    }

    if (second_contributory || (intno == EXCP0E_PAGE) ||
        (intno == EXCP08_DBLE)) {
        env->old_exception = intno;
    }

    return intno;
}

/*
 * The DR6 bits of a #DB, written as it is delivered: B0-B3 are cleared
 * first, as Linux 7.3's KVM does (kvm_deliver_exception_payload()) and the
 * Intel SDM 325462-093 Vol. 3B, 20.2.3 allows, and BD clears DR7.GD (Intel
 * SDM 325462-093 Vol. 3B, 20.2.4).
 */
static void debug_payload_apply(CPUX86State *env, int intno)
{
    uint32_t payload = env->db_payload;

    if (intno == EXCP01_DB && payload) {
        env->dr[6] = (env->dr[6] & ~0xf) | payload;
        if (payload & DR6_BD) {
            env->dr[7] &= ~DR7_GD;
        }
        env->db_payload = 0;
    }
}

/*
 * Signal an interruption. It is executed in the main CPU loop.
 * is_int is TRUE if coming from the int instruction. next_eip is the
 * env->eip value AFTER the interrupt instruction. It is only relevant if
 * is_int is TRUE.
 */
static G_NORETURN
void raise_interrupt2(CPUX86State *env, int intno,
                      int is_int, int error_code,
                      int next_eip_addend,
                      uintptr_t retaddr)
{
    CPUState *cs = env_cpu(env);
    uint64_t last_pc = env->eip + env->segs[R_CS].base;

    if (!is_int) {
        /*
         * The DR6 bits of a #DB are its event data under FRED (Intel SDM
         * 325462-093 Vol. 3A, 8.3.2.1).
         */
        if (intno == EXCP01_DB) {
            env->db_event = env->db_payload & (0xf | DR6_BD | DR6_BS);
        }
        /*
         * A #DB writes DR6 and DR7 before an SVM intercept (AMD64
         * Architecture Programmer's Manual Volume 2, 24593 rev. 3.45,
         * 15.12.2), but not before a VMX exit, which takes the bits as its
         * qualification (Intel SDM 325462-093 Vol. 3C, 30.1).
         */
        if (!env->vmx.nonroot) {
            debug_payload_apply(env, intno);
        }
        cpu_svm_check_intercept_param(env, SVM_EXIT_EXCP_BASE + intno,
                                      error_code, retaddr);
        intno = check_exception(env, intno, &error_code, retaddr);
#if !defined(CONFIG_USER_ONLY)
        /* The double fault an exception became may exit too. */
        if (intno == EXCP08_DBLE && env->vmx.nonroot) {
            x86_vmx_check_intercept(env, SVM_EXIT_EXCP_BASE + EXCP08_DBLE,
                                    0, retaddr);
        }
#endif
        debug_payload_apply(env, intno);
    } else {
        /* Decode assists: the vector of INTn. */
        uint64_t info = env->features[FEAT_SVM] & CPUID_SVM_DECODEASSIST ?
                        intno : 0;

        env->svm_insn_len = next_eip_addend;
        cpu_svm_check_intercept_param(env, SVM_EXIT_SWINT, info, retaddr);
    }

    cs->exception_index = intno;
    env->error_code = error_code;
    env->exception_is_int = is_int;
    env->exception_next_eip = env->eip + next_eip_addend;
    qemu_plugin_vcpu_exception_cb(cs, last_pc);
    cpu_loop_exit_restore(cs, retaddr);
}

/* shortcuts to generate exceptions */

G_NORETURN void raise_interrupt(CPUX86State *env, int intno, int next_eip_addend)
{
#if !defined(CONFIG_USER_ONLY)
    x86_pmu_soft_int(env);
#endif
    raise_interrupt2(env, intno, 1, 0, next_eip_addend, 0);
}

/*
 * INT3 (opcode CCh) and INTO raise #BP and #OF with the privilege checks and
 * return address of a software interrupt, but SVM intercepts them as those
 * exceptions, not as INTn (AMD64 Architecture Programmer's Manual Volume 2,
 * 24593 rev. 3.45, 15.12).
 */
G_NORETURN void raise_trap_instruction(CPUX86State *env, int intno,
                                       int next_eip_addend)
{
    CPUState *cs = env_cpu(env);
    uint64_t last_pc = env->eip + env->segs[R_CS].base;

    env->svm_insn_len = next_eip_addend;
#if !defined(CONFIG_USER_ONLY)
    x86_pmu_soft_int(env);
    if (env->vmx.nonroot) {
        env->vmx.soft_exception = X86_VMX_SOFT_EXCEPTION;
    }
#endif
    cpu_svm_check_intercept_param(env, SVM_EXIT_EXCP_BASE + intno, 0, 0);
#if !defined(CONFIG_USER_ONLY)
    /* FRED event delivery tells them from INT n by it too. */
    if (env->cr[4] & CR4_FRED_MASK) {
        env->vmx.soft_exception = X86_VMX_SOFT_EXCEPTION;
    }
#endif

    cs->exception_index = intno;
    env->error_code = 0;
    env->exception_is_int = 1;
    env->exception_next_eip = env->eip + next_eip_addend;
    qemu_plugin_vcpu_exception_cb(cs, last_pc);
    cpu_loop_exit(cs);
}

G_NORETURN void raise_exception_err(CPUX86State *env, int exception_index,
                                    int error_code)
{
    raise_interrupt2(env, exception_index, 0, error_code, 0, 0);
}

G_NORETURN void raise_exception_err_ra(CPUX86State *env, int exception_index,
                                       int error_code, uintptr_t retaddr)
{
    raise_interrupt2(env, exception_index, 0, error_code, 0, retaddr);
}

G_NORETURN void raise_exception(CPUX86State *env, int exception_index)
{
    raise_interrupt2(env, exception_index, 0, 0, 0, 0);
}

G_NORETURN void raise_exception_ra(CPUX86State *env, int exception_index,
                                   uintptr_t retaddr)
{
    raise_interrupt2(env, exception_index, 0, 0, 0, retaddr);
}

/*
 * A #DB of the DR6 bits PAYLOAD (B0-B3, BD, BS, BT), merged with the debug
 * exceptions a VM entry left pending and those MOV SS or POP SS held.
 */
G_NORETURN void raise_debug_exception(CPUX86State *env, uint32_t payload,
                                      uintptr_t retaddr)
{
    env->db_payload = payload | env->vmx.db_held | env->db_movss;
    env->vmx.db_held = 0;
    env->db_movss = 0;
    raise_exception_ra(env, EXCP01_DB, retaddr);
}

G_NORETURN void HELPER(icebp)(CPUX86State *env, uint32_t len)
{
    CPUState *cs = env_cpu(env);

#if !defined(CONFIG_USER_ONLY)
    /*
     * VMX takes INT1 as a privileged software exception, whose VM exits,
     * also those of faults in its delivery, report its length (Intel SDM
     * 325462-093 Vol. 3C, 30.2.5).
     */
    env->svm_insn_len = len;
    if (env->vmx.nonroot) {
        env->vmx.soft_exception = X86_VMX_PRIV_SOFT_EXCEPTION;
        if (x86_vmx_exception_exits(env, EXCP01_DB, 0)) {
            x86_vmx_check_intercept(env, SVM_EXIT_EXCP_BASE + EXCP01_DB, 0,
                                    GETPC());
        }
        env->vmx.soft_exception = X86_VMX_PRIV_SOFT_EXCEPTION;
    }
    /* So does FRED event delivery. */
    if (env->cr[4] & CR4_FRED_MASK) {
        env->vmx.soft_exception = X86_VMX_PRIV_SOFT_EXCEPTION;
    }
#endif
    do_end_instruction(env);

    /* The data breakpoints MOV SS or POP SS held join ICEBP's #DB. */
    env->db_event = env->db_movss & 0xf;
    if (env->db_movss) {
        env->dr[6] = (env->dr[6] & ~0xf) | env->db_movss;
        env->db_movss = 0;
    }

    /*
     * INT1 aka ICEBP generates a trap-like #DB, but it is pretty special.
     *
     * "Although the ICEBP instruction dispatches through IDT vector 1,
     * that event is not interceptable by means of the #DB exception
     * intercept".  Instead there is a separate fault-like ICEBP intercept.
     */
    cs->exception_index = EXCP01_DB;
    env->error_code = 0;
    env->exception_is_int = 0;
    env->exception_next_eip = env->eip;
    cpu_loop_exit(cs);
}

G_NORETURN void handle_unaligned_access(CPUX86State *env, vaddr vaddr,
                                        MMUAccessType access_type,
                                        uintptr_t retaddr)
{
    /*
     * With alignment checking on, at CPL 3 with CR0.AM and EFLAGS.AC, the
     * translator asks data accesses of 8 bytes or less for their natural
     * alignment, whose violation raises #AC(0) (Intel SDM 325462-093 Vol.
     * 3A, Event 17), and checks those needing 16-byte alignment itself.
     */
    if ((env->hflags & HF_CPL_MASK) == 3 && (env->eflags & AC_MASK) &&
        (env->cr[0] & CR0_AM_MASK)) {
        raise_exception_err_ra(env, EXCP11_ALGN, 0, retaddr);
    }

    /*
     * Otherwise unaligned accesses are only triggered by SSE/AVX
     * instructions that impose alignment requirements on memory
     * operands. These instructions raise #GP(0) upon accessing an
     * unaligned address.
     */
    raise_exception_ra(env, EXCP0D_GPF, retaddr);
}
