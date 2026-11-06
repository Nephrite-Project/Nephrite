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
void x86_eff_freq_halt(CPUX86State *env, bool halted);
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
G_NORETURN void raise_debug_exception(CPUX86State *env, uint32_t payload,
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
/*
 * Guest mode's sets of MMU indexes: entering the guest context TAG gives,
 * with the set that holds its translations, emptied too with FLUSH; the
 * context of the set guest mode uses; and none held, after a flush of all.
 */
void x86_guest_tlb_enter(CPUX86State *env, const X86GuestTLBTag *tag,
                         bool flush);
X86GuestTLBTag *x86_guest_tlb_current(CPUX86State *env);
void x86_guest_tlb_forget(CPUX86State *env);
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

/* seg_helper.c */
/* What a data access does with its segment, for x86_seg_access_ok(). */
#define X86_SEG_READ         1
#define X86_SEG_WRITE        2 /* writes, and may read */
#define X86_SEG_ANY          3 /* any type, as CLFLUSH */
bool x86_seg_access_ok(CPUX86State *env, int seg, target_ulong ofs,
                       uint32_t size, int access);

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
void x86_vmx_init(X86CPU *cpu);
bool x86_vmx_holds_init(CPUX86State *env);
/* HELPER(user_wait)'s INFO: the source register, and UMWAIT not TPAUSE. */
#define USER_WAIT_REG 31
#define USER_WAIT_UMWAIT 32
void x86_user_wait_init(X86CPU *cpu);
void x86_user_wait_end(CPUX86State *env);
void x86_vmx_smm_enter(CPUX86State *env);
void x86_vmx_smm_leave(CPUX86State *env);
G_NORETURN void x86_vmx_exit(CPUX86State *env, uint32_t reason,
                             uint64_t qual, uintptr_t ra);
G_NORETURN void x86_vmx_exit_full(CPUX86State *env, uint32_t reason,
                                  uint64_t qual, uint32_t intr_info,
                                  uint32_t intr_error, uintptr_t ra);
void x86_vmx_check_intercept(CPUX86State *env, uint32_t type,
                             uint64_t param, uintptr_t ra);
void x86_vmx_check_io(CPUX86State *env, uint32_t port, uint32_t svm_flags,
                      uintptr_t ra);
bool x86_vmx_exception_exits(CPUX86State *env, int vector,
                             uint32_t error_code);
uint64_t x86_vmx_cr_write(CPUX86State *env, int cr, uint64_t val, int gpr,
                          uintptr_t ra);
target_ulong x86_vmx_cr_read(CPUX86State *env, int cr);
bool x86_vmx_tpr_shadow(CPUX86State *env);
target_ulong x86_vmx_read_cr8(CPUX86State *env);
void x86_vmx_write_cr8(CPUX86State *env, target_ulong val, uintptr_t ra);
G_NORETURN void x86_vmx_apic_fetch_exit(CPUX86State *env, vaddr addr,
                                        uintptr_t ra);
uint64_t x86_vmx_apic_read(CPUX86State *env, hwaddr offset, unsigned size,
                           uintptr_t ra);
void x86_vmx_apic_write(CPUX86State *env, hwaddr offset, uint64_t val,
                        unsigned size, uintptr_t ra);
bool x86_vmx_x2apic_rdmsr(CPUX86State *env, uint32_t msr, uint64_t *val);
bool x86_vmx_x2apic_wrmsr(CPUX86State *env, uint32_t msr, uint64_t val,
                          uintptr_t ra);
bool x86_vmx_clts(CPUX86State *env, uintptr_t ra);
uint32_t x86_vmx_lmsw(CPUX86State *env, uint32_t src, bool mem,
                      uintptr_t ra);
void x86_vmx_task_switch(CPUX86State *env, int selector, int source,
                         uintptr_t ra);
void x86_vmx_event_start(CPUX86State *env, int intno, int is_int,
                         int error_code, int is_hw, bool has_error_code);
void x86_vmx_event_end(CPUX86State *env);
void x86_vmx_do_vmexit(CPUX86State *env);
G_NORETURN void x86_vmx_mtf_step(CPUX86State *env, uint32_t traps);
bool x86_vmx_take_interrupt(CPUX86State *env, int request, bool woke);
bool x86_vmx_virtual_nmis(CPUX86State *env);
bool x86_vmx_rdtscp_allowed(CPUX86State *env);
uint64_t x86_vmx_tsc(CPUX86State *env, uint64_t tsc);
void x86_vmx_tsc_seen(CPUX86State *env);
uint64_t x86_vmx_tsc_delay(CPUX86State *env, uint64_t delay);
bool x86_vmx_user_wait_enabled(CPUX86State *env);
void x86_vmx_user_wait_exit(CPUX86State *env, uint32_t reason, int reg,
                            uintptr_t ra);
void x86_vmx_invpcid(CPUX86State *env, uint32_t info, uint64_t eii,
                     target_ulong disp, uintptr_t ra);
void x86_vmx_rdrand(CPUX86State *env, uint32_t info, uintptr_t ra);
bool x86_vmx_ept_active(CPUX86State *env);
void x86_vmx_desc_exit(CPUX86State *env, uint32_t type, uint32_t info,
                       uint64_t eii, target_ulong disp, uintptr_t ra);
bool x86_vmx_ept_mbec(CPUX86State *env);
bool x86_vmx_ept_ad(CPUX86State *env);
bool x86_vmx_ept_translate(CPUX86State *env, hwaddr gpa,
                           MMUAccessType access, bool supervisor,
                           hwaddr *hpa, int *prot, int *page_size);
void x86_vmx_ept_guest_page(CPUX86State *env, uint64_t flags);
G_NORETURN void x86_vmx_ept_exit(CPUX86State *env, hwaddr gpa,
                                 target_ulong linear, bool final,
                                 uintptr_t ra);
bool x86_vmx_senduipi(CPUX86State *env, uint32_t ndst, uint8_t nv,
                      uintptr_t ra);
G_NORETURN void x86_vmx_pdpte_exit(CPUX86State *env, hwaddr gpa,
                                   uintptr_t ra);
void x86_svm_late_intercept(CPUX86State *env, uint32_t type, uintptr_t ra);
#endif

/* system/misc_helper.c */
#ifndef CONFIG_USER_ONLY
uint64_t x86_efer_writable(CPUX86State *env);
bool x86_cpu_wrmsr(CPUX86State *env, uint32_t msr, uint64_t val);
bool x86_cpu_rdmsr(CPUX86State *env, uint32_t msr, uint64_t *val);
void x86_amd_cpuid_hide(CPUX86State *env, uint32_t leaf, uint32_t subleaf,
                        uint32_t *eax, uint32_t *ebx, uint32_t *ecx,
                        uint32_t *edx);
/* Whether paging is PAE paging (Intel SDM 325462-093 Vol. 3A, 5.1.1). */
static inline bool x86_pae_paging(uint64_t cr0, uint64_t cr4, uint64_t efer)
{
    return (cr0 & CR0_PG_MASK) && (cr4 & CR4_PAE_MASK) &&
           !(efer & MSR_EFER_LME);
}
bool x86_read_pdptes(CPUX86State *env, uint64_t cr3, uint64_t *pdpte,
                     uintptr_t ra);
bool x86_load_pdptes(CPUX86State *env);
#endif

/*
 * The third insn_start word: the instruction's length, and where the TB
 * counts for the PMU, whether the instruction counted a branch and a
 * mispredicted one, and its index in the TB.
 */
#define X86_PMU_INSN_LEN 0x1f
#define X86_PMU_INSN_BRANCH 0x20
#define X86_PMU_INSN_MISPREDICT 0x40
#define X86_PMU_INSN_INDEX_SHIFT 8
/* The instruction's data accesses all go through SS. */
#define X86_INSN_STACK 0x80

/* system/pmu.c */
#ifndef CONFIG_USER_ONLY
bool x86_pmu_enabled(CPUX86State *env);
unsigned x86_pmu_bucket(uint32_t hflags);
void x86_pmu_reconfigure(CPUX86State *env);
int x86_pmu_rdmsr(CPUX86State *env, uint32_t msr, uint64_t *val);
int x86_pmu_wrmsr(CPUX86State *env, uint32_t msr, uint64_t val);
bool x86_pmu_global_ctrl_valid(uint64_t val);
void x86_pmu_set_global_ctrl(CPUX86State *env, uint64_t val);
bool x86_pmu_rdpmc(CPUX86State *env);
void x86_pmu_restore(CPUX86State *env, const TranslationBlock *tb,
                     uint64_t word);
void x86_pmu_restored_retired(CPUX86State *env);
void x86_pmu_soft_int(CPUX86State *env);
void x86_pmu_event_start(CPUX86State *env, int is_int);
void x86_pmu_event_end(CPUX86State *env);
#endif

/* system/cet_helper.c */
#ifndef CONFIG_USER_ONLY
/* The shadow-stack work that a far RET or IRET does last. */
typedef struct X86ShstkReturn {
    bool set;           /* SSP becomes ssp */
    uint64_t ssp;
    bool release;       /* the supervisor shadow-stack token at token frees */
    uint64_t token;
} X86ShstkReturn;

/* A task switch's frame of the old task's CS, LIP, and SSP. */
typedef struct X86ShstkTask {
    uint64_t cs;
    uint64_t lip;
    uint64_t ssp;
} X86ShstkTask;

/* Bits 63:N take bit N - 1, N being the processor's linear-address width. */
uint64_t x86_la_adjust(CPUX86State *env, uint64_t addr);
/* IA32_PL3_SSP := SSP, the user SSP that a transfer from CPL 3 leaves. */
void x86_shstk_save_user(CPUX86State *env);
bool x86_shstk_acquire(CPUX86State *env, uint64_t addr, uintptr_t ra);
void x86_shstk_release(CPUX86State *env, uint64_t addr, uintptr_t ra);
/* A far CALL to a code segment, to a 64-bit one where to64 is set. */
void x86_shstk_far_call(CPUX86State *env, bool to64, uint32_t cs,
                        uint64_t lip, uintptr_t ra);
/*
 * A far CALL through a call gate or an event's delivery through an
 * interrupt or trap gate, from CPL cpl to dpl, with the CS and LIP to
 * return to; ist is the IST index of an IA-32e mode gate, else 0.
 */
void x86_shstk_enter(CPUX86State *env, int cpl, int dpl, int ist, bool to64,
                     uint32_t cs, uint64_t lip, uintptr_t ra);
/*
 * A far RET or IRET from CPL cpl to RPL rpl, to CS cs at LIP lip, to 64-bit
 * code where to64 is set: checks the shadow stack, then gives in r what
 * x86_shstk_return_commit() does once nothing else can fault.
 */
void x86_shstk_return(CPUX86State *env, X86ShstkReturn *r, bool iret,
                      int cpl, int rpl, uint32_t cs, uint64_t lip, bool to64,
                      uintptr_t ra);
void x86_shstk_return_commit(CPUX86State *env, const X86ShstkReturn *r,
                             uintptr_t ra);
void x86_shstk_task_pop(CPUX86State *env, X86ShstkTask *t, uintptr_t ra);
void x86_shstk_task_push(CPUX86State *env, const X86ShstkTask *t,
                         uintptr_t ra);
/*
 * A far CALL or JMP, an event's delivery, SYSCALL, SYSENTER, or a task
 * switch other than IRET's, to CPL cpl: where indirect branch tracking is
 * on there, its tracker waits for an ENDBRANCH, unsuppressed (Intel SDM
 * 325462-093 Vol. 1, 18.3.3).
 */
void x86_ibt_far(CPUX86State *env, int cpl);
/* ShadowStackPush of 8 bytes at the CPL. */
void x86_shstk_push(CPUX86State *env, uint64_t val, uintptr_t ra);
/* A pop of 8 bytes at the CPL that must give val, else #CP(code). */
void x86_shstk_pop_check(CPUX86State *env, uint64_t val, int code,
                         uintptr_t ra);
#ifdef TARGET_X86_64
/*
 * FRED event delivery's supervisor shadow-stack frame below *ssp: 4 bytes
 * of zeros, then, 8-byte aligned, CS, LIP, and the old SSP.
 */
void x86_shstk_fred_push(CPUX86State *env, uint64_t *ssp, uint64_t cs,
                         uint64_t lip, uint64_t old_ssp);
/* ERETS's pops of that frame, from *ssp. */
void x86_shstk_fred_pop(CPUX86State *env, uint64_t *ssp, uint64_t *old_ssp,
                        uint64_t *lip, uint64_t *cs, uintptr_t ra);
#endif
#endif

/* system/uintr_helper.c */
#ifndef CONFIG_USER_ONLY
uint8_t x86_uintr_uinv(CPUX86State *env);
void x86_uintr_set_uinv(CPUX86State *env, uint8_t uinv);
void x86_uintr_recognize(CPUX86State *env);
bool x86_uintr_msr_valid(CPUX86State *env, uint32_t msr, uint64_t val);
int x86_uintr_rdmsr(CPUX86State *env, uint32_t msr, uint64_t *val);
int x86_uintr_wrmsr(CPUX86State *env, uint32_t msr, uint64_t val);
void x86_uintr_deliver(CPUX86State *env);
void x86_uintr_process(CPUX86State *env);
bool x86_uintr_notification(CPUX86State *env, int vector);
#endif

/* The VMX interruption types of INT1 and of INT3 and INTO. */
#define X86_VMX_PRIV_SOFT_EXCEPTION 5
#define X86_VMX_SOFT_EXCEPTION 6

/*
 * The event types of VMX and FRED (Intel SDM 325462-093 Vol. 3A, 8.3.2.1):
 * external interrupt, NMI, hardware exception, INT n, INT1, INT3 or INTO,
 * and SYSCALL or SYSENTER.
 */
#define X86_EVENT_EXT_INTR 0
#define X86_EVENT_NMI 2
#define X86_EVENT_HW_EXCEPTION 3
#define X86_EVENT_SW_INTR 4
#define X86_EVENT_PRIV_SW_EXCEPTION X86_VMX_PRIV_SOFT_EXCEPTION
#define X86_EVENT_SW_EXCEPTION X86_VMX_SOFT_EXCEPTION
#define X86_EVENT_OTHER 7

/* The type of the event that do_interrupt_all() delivers. */
static inline int x86_event_type(CPUX86State *env, int intno, int is_int,
                                 int is_hw)
{
    if (is_hw) {
        return intno == EXCP02_NMI ? X86_EVENT_NMI : X86_EVENT_EXT_INTR;
    }
    if (env->vmx.soft_exception) {
        return env->vmx.soft_exception;
    }
    return is_int ? X86_EVENT_SW_INTR : X86_EVENT_HW_EXCEPTION;
}

/*
 * The event data of an event of TYPE and VECTOR that FRED event delivery
 * saves (Intel SDM 325462-093 Vol. 3A, 8.3.2.1): the linear address of a
 * page fault, the debug conditions of a #DB, else 0.
 */
static inline uint64_t x86_fred_event_data(CPUX86State *env, int type,
                                           int vector)
{
    if (type == X86_EVENT_HW_EXCEPTION && vector == EXCP0E_PAGE) {
        return env->cr[2];
    }
    /* The NMI-source bitmap of the NMI being taken (7.7.3). */
    if (type == X86_EVENT_NMI) {
        return env->features[FEAT_7_1_EAX] & CPUID_7_1_EAX_NMI_SRC ?
               env->nmi_source_taken : 0;
    }
    if (vector == EXCP01_DB && (type == X86_EVENT_HW_EXCEPTION ||
                                type == X86_EVENT_PRIV_SW_EXCEPTION)) {
        return env->db_event;
    }
    return 0;
}

/* seg_helper.c, FRED */
/* IA32_FRED_CONFIG's reserved bits (Intel SDM 325462-093 Vol. 3A, 8.2.3). */
#define FRED_CONFIG_RESERVED 0x834ULL
#if !defined(CONFIG_USER_ONLY) && defined(TARGET_X86_64)
void x86_fred_deliver(CPUX86State *env, int type, int vector, int error_code,
                      bool has_error_code, int len, target_ulong old_rip);
int x86_fred_rdmsr(CPUX86State *env, uint32_t msr, uint64_t *val);
int x86_fred_wrmsr(CPUX86State *env, uint32_t msr, uint64_t val);
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
uint32_t hw_breakpoint_hits(CPUX86State *env, bool *enabled);
uint32_t hw_data_breakpoint_hits(CPUX86State *env, bool *enabled);
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

/*
 * A PAT value with one of the memory types UC, WC, WT, WP, WB, and UC- in
 * every entry, which WRMSR takes; other encodings and reserved bits make it
 * raise #GP (Intel SDM 325462-093 Vol. 3A, 14.12.2 and 14.12.4; AMD64
 * Architecture Programmer's Manual Volume 2, 24593 rev. 3.46, 7.8.1).
 */
static inline bool x86_pat_valid(uint64_t pat)
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
 * The single-step trap TF leaves pending after an instruction, as DR6
 * bits: after any with DebugCtl.BTF clear, after a branch with it set.
 */
static inline uint32_t x86_step_trap(CPUX86State *env, bool branch)
{
    if ((env->eflags & TF_MASK) &&
        (branch || !(env->debugctl & DEBUGCTL_BTF))) {
        return DR6_BS;
    }
    return 0;
}
#endif /* I386_HELPER_TCG_H */
