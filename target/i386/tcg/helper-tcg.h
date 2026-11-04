/*
 * TCG specific prototypes for helpers
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef I386_HELPER_TCG_H
#define I386_HELPER_TCG_H

#include "qemu/host-utils.h"

/* Maximum instruction code size */
#define TARGET_MAX_INSN_SIZE 16

#if defined(TARGET_X86_64)
# define TCG_PHYS_ADDR_BITS 40
#else
# define TCG_PHYS_ADDR_BITS 36
#endif

/**
 * x86_cpu_do_interrupt:
 * @cpu: vCPU the interrupt is to be handled by.
 */
void x86_cpu_do_interrupt(CPUState *cpu);
#ifndef CONFIG_USER_ONLY
void x86_cpu_poll_during_halt(CPUState *cpu);
void x86_cpu_leaving_halt(CPUState *cpu);
bool x86_need_replay_interrupt(int interrupt_request);
bool x86_cpu_exec_interrupt(CPUState *cpu, int int_req);
#endif

void breakpoint_handler(CPUState *cs);

/* n must be a constant to be efficient */
static inline target_long lshift(target_long x, int n)
{
    if (n >= 0) {
        return x << n;
    } else {
        return x >> (-n);
    }
}

/* translate.c */
void tcg_x86_init(void);
void x86_translate_code(CPUState *cs, TranslationBlock *tb,
                        int *max_insns, vaddr pc, void *host_pc);

/* excp_helper.c */
G_NORETURN void raise_exception(CPUX86State *env, int exception_index);
G_NORETURN void raise_exception_ra(CPUX86State *env, int exception_index,
                                   uintptr_t retaddr);
G_NORETURN void raise_exception_err(CPUX86State *env, int exception_index,
                                    int error_code);
G_NORETURN void raise_exception_err_ra(CPUX86State *env, int exception_index,
                                       int error_code, uintptr_t retaddr);
G_NORETURN void raise_interrupt(CPUX86State *nenv, int intno, int next_eip_addend);
G_NORETURN void raise_trap_instruction(CPUX86State *env, int intno,
                                       int next_eip_addend);
G_NORETURN void handle_unaligned_access(CPUX86State *env, vaddr vaddr,
                                        MMUAccessType access_type,
                                        uintptr_t retaddr);
#ifdef CONFIG_USER_ONLY
void x86_cpu_record_sigsegv(CPUState *cs, vaddr addr,
                            MMUAccessType access_type,
                            bool maperr, uintptr_t ra);
void x86_cpu_record_sigbus(CPUState *cs, vaddr addr,
                           MMUAccessType access_type, uintptr_t ra);
#else
bool x86_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                      MMUAccessType access_type, int mmu_idx,
                      bool probe, uintptr_t retaddr);
G_NORETURN void x86_cpu_do_unaligned_access(CPUState *cs, vaddr vaddr,
                                            MMUAccessType access_type,
                                            int mmu_idx, uintptr_t retaddr);
#endif

/* cc_helper.c */
static inline unsigned int compute_pf(uint8_t x)
{
    return !parity8(x) * CC_P;
}

/* misc_helper.c */
void cpu_load_eflags(CPUX86State *env, int eflags, int update_mask);
uint64_t x86_tsc_read(CPUX86State *env);

/* system/svm_helper.c */
#ifndef CONFIG_USER_ONLY
G_NORETURN void cpu_vmexit(CPUX86State *nenv, uint64_t exit_code,
                           uint64_t exit_info_1, uintptr_t retaddr);
void do_vmexit(CPUX86State *env);
target_ulong svm_next_rip(CPUX86State *env);

/* system/avic.c */
void svm_avic_init(X86CPU *cpu);
void svm_avic_request(CPUX86State *env);
bool svm_avic_has_interrupt(CPUX86State *env);
int svm_avic_take_interrupt(CPUX86State *env);
void svm_avic_set_tpr(CPUX86State *env, uint32_t tpr);
void svm_avic_doorbell(CPUX86State *env, uint32_t apic_id);
bool svm_x2avic_rdmsr(CPUX86State *env, uint32_t msr, uint64_t *val,
                      uintptr_t retaddr);
bool svm_x2avic_wrmsr(CPUX86State *env, uint32_t msr, uint64_t val,
                      uintptr_t retaddr);
#endif

/* system/vmx_helper.c */
#ifndef CONFIG_USER_ONLY
uint64_t x86_vmcs_read(CPUX86State *env, uint32_t encoding);
void x86_vmcs_write(CPUX86State *env, uint32_t encoding, uint64_t val);
bool x86_vmx_cr_valid(CPUX86State *env, int cr, uint64_t val);
bool x86_vmx_read_msr(CPUX86State *env, uint32_t index, uint64_t *val);
bool x86_feature_control_exists(CPUX86State *env);
bool x86_feature_control_write(CPUX86State *env, uint64_t val);
bool x86_vmx_holds_init(CPUX86State *env);
void x86_vmx_smm_enter(CPUX86State *env);
void x86_vmx_smm_leave(CPUX86State *env);
#endif

/* seg_helper.c */
void do_interrupt_x86_hardirq(CPUX86State *env, int intno, int is_hw);
void do_interrupt_all(X86CPU *cpu, int intno, int is_int,
                      int error_code, target_ulong next_eip, int is_hw);
void handle_even_inj(CPUX86State *env, int intno, int is_int,
                     int error_code, int is_hw, int rm);
int exception_has_error_code(int intno);

/* smm_helper.c */
void do_smm_enter(X86CPU *cpu);

/* system/bpt_helper.c */
bool check_hw_breakpoints(CPUX86State *env, bool force_dr6_update);
bool x86_debug_check_watchpoint(CPUState *cs, CPUWatchpoint *wp);

/*
 * Do the tasks usually performed by gen_eob().  Callers of this function
 * should also handle TF as appropriate.
 */
static inline void do_end_instruction(CPUX86State *env)
{
    /* needed if sti is just before */
    env->hflags &= ~HF_INHIBIT_IRQ_MASK;
    env->eflags &= ~HF_RF_MASK;
}
#endif /* I386_HELPER_TCG_H */
