/*
 * i386 TCG cpu class initialization
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

#include "qemu/osdep.h"
#include "cpu.h"
#include "helper-tcg.h"
#include "qemu/accel.h"
#include "accel/accel-cpu-target.h"
#include "exec/translation-block.h"
#include "exec/target_page.h"
#include "accel/tcg/cpu-ops.h"
#include "tcg-cpu.h"

/* Frob eflags into and out of the CPU temporary format.  */

static void x86_cpu_exec_enter(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    CC_SRC = env->eflags & (CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
    env->df = 1 - (2 * ((env->eflags >> 10) & 1));
    CC_OP = CC_OP_EFLAGS;
    env->eflags &= ~(DF_MASK | CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
    cpu->eflags_in_tcg = true;
#ifndef CONFIG_USER_ONLY
    /* State loaded from elsewhere, as by migration, may watch bus locks. */
    if (unlikely((env->debugctl & DEBUGCTL_BLD) || env->memory_ctrl)) {
        x86_bus_lock_watch(env);
    }
#endif
}

static void x86_cpu_exec_exit(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    env->eflags = cpu_compute_eflags(env);
    cpu->eflags_in_tcg = false;
#ifndef CONFIG_USER_ONLY
    /*
     * A halt starts where TCG stops running the processor for it; UMWAIT and
     * TPAUSE wait in C0's substates, where MPERF counts.
     */
    if (cs->halted && !env->user_wait) {
        x86_eff_freq_halt(env, true);
    }
#endif
}

#ifndef CONFIG_USER_ONLY
/*
 * The checks data accesses through a segment need outside 64-bit mode.  In
 * real-address and virtual-8086 mode only its limit counts; in protected
 * mode, writable expand-up data segments only need their limit checked.
 */
static uint64_t x86_seg_class(const SegmentCache *sc, bool pm)
{
    const uint32_t type = DESC_P_MASK | DESC_S_MASK | DESC_CS_MASK |
                          DESC_E_MASK | DESC_W_MASK;

    if (pm &&
        (sc->flags & type) != (DESC_P_MASK | DESC_S_MASK | DESC_W_MASK)) {
        return TB_SEG_SLOW;
    }
    if (sc->limit == 0xffffffff) {
        return TB_SEG_FLAT;
    }
    return sc->limit == 0xffff ? TB_SEG_64K : TB_SEG_LIMIT;
}

/*
 * The TB flags of segment limit and type checks (Intel SDM 325462-093
 * Vol. 3A, 6.3 and 6.4).
 */
static uint64_t x86_seg_tb_flags(CPUX86State *env)
{
    bool pm = (env->cr[0] & CR0_PE_MASK) && !(env->eflags & VM_MASK);
    uint32_t limit = env->segs[R_CS].limit;
    uint64_t flags = 0;
    int i;

    for (i = R_ES; i <= R_GS; i++) {
        flags |= x86_seg_class(&env->segs[i], pm) <<
                 (TB_SEG_SHIFT + i * 2);
    }
    if (limit == 0xffff) {
        flags |= (uint64_t)TB_SEG_64K << TB_FETCH_SHIFT;
    } else if (limit != 0xffffffff) {
        flags |= (uint64_t)TB_SEG_LIMIT << TB_FETCH_SHIFT |
                 (uint64_t)((limit + 1) & 0xfff) << TB_FETCH_END_SHIFT;
    }
    return flags;
}
#endif

static TCGTBCPUState x86_get_tb_cpu_state(CPUState *cs)
{
    CPUX86State *env = cpu_env(cs);
    uint32_t flags, cs_base;
    uint64_t more_flags = 0;
    vaddr pc;

    flags = env->hflags |
        (env->eflags & (IOPL_MASK | TF_MASK | RF_MASK | VM_MASK | AC_MASK));
    /*
     * At CPL 3, where AC does not choose an MMU index for SMAP, AC stands
     * for alignment checking, which CR0.AM must enable too.
     */
    if ((flags & HF_CPL_MASK) == 3 && !(env->cr[0] & CR0_AM_MASK)) {
        flags &= ~AC_MASK;
    }
    if (unlikely(env->debugctl & DEBUGCTL_LBR)) {
        flags |= HF_LBR_MASK;
    }
    /* With DebugCtl.BTF, TF single-steps only control transfers. */
    if (unlikely(env->debugctl & DEBUGCTL_BTF) && (flags & HF_TF_MASK)) {
        flags = (flags & ~HF_TF_MASK) | HF_BTF_MASK;
    }
    /* VMX's monitor trap flag steps every instruction, as TF does. */
    if (unlikely(x86_vmx_mtf(env))) {
        flags |= HF_TF_MASK;
    }
    if (unlikely(env->cr[4] & CR4_CET_MASK) && (env->cr[0] & CR0_PE_MASK) &&
        !(env->eflags & VM_MASK)) {
        uint64_t cet = (flags & HF_CPL_MASK) == 3 ? env->u_cet : env->s_cet;

        if (cet & CET_SH_STK_EN) {
            more_flags |= TB_SHSTK;
        }
        if (cet & CET_ENDBR_EN) {
            more_flags |= TB_IBT |
                          (cet & CET_SUPPRESS ? TB_IBT_SUPPRESS : 0) |
                          (cet & CET_NO_TRACK_EN ? TB_IBT_NOTRACK : 0) |
                          (cet & CET_WAIT_ENDBR ? TB_IBT_WAIT : 0);
        }
    }
    /*
     * Past MOV SS's or POP SS's shadow, the #DB of their data breakpoints
     * comes first, where the next instruction or the handler of its event
     * starts.
     */
    if (unlikely(env->db_movss) && !(env->hflags & HF_INHIBIT_IRQ_MASK)) {
        more_flags |= TB_DB_PENDING;
    }
    if (env->hflags & HF_CS64_MASK) {
        cs_base = 0;
        pc = env->eip;
        if (env->cr[4] & CR4_LA57_MASK) {
            more_flags |= TB_LA57;
        }
        if (env->efer & MSR_EFER_UAIE) {
            more_flags |= TB_UAI;
        }
        if ((env->efer & MSR_EFER_LMSLE) && (env->hflags & HF_CPL_MASK)) {
            more_flags |= TB_LMSLE;
        }
    } else {
        cs_base = env->segs[R_CS].base;
        pc = (uint32_t)(cs_base + env->eip);
#ifndef CONFIG_USER_ONLY
        more_flags |= x86_seg_tb_flags(env);
#endif
    }

    return (TCGTBCPUState){
        .pc = pc, .flags = flags, .cs_base = cs_base | more_flags
    };
}

static void x86_cpu_synchronize_from_tb(CPUState *cs,
                                        const TranslationBlock *tb)
{
    /* The instruction pointer is always up to date with CF_PCREL. */
    if (!(tb_cflags(tb) & CF_PCREL)) {
        CPUX86State *env = cpu_env(cs);

        if (tb->flags & HF_CS64_MASK) {
            env->eip = tb->pc;
        } else {
            env->eip = (uint32_t)(tb->pc - (tb->cs_base & TB_CS_BASE_MASK));
        }
    }
}

static void x86_restore_state_to_opc(CPUState *cs,
                                     const TranslationBlock *tb,
                                     const uint64_t *data)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    int cc_op = data[1];
    uint64_t new_pc;

    if (tb_cflags(tb) & CF_PCREL) {
        /*
         * data[0] in PC-relative TBs is also a linear address, i.e. an address with
         * the CS base added, because it is not guaranteed that EIP bits 12 and higher
         * stay the same across the translation block.  Add the CS base back before
         * replacing the low bits, and subtract it below just like for !CF_PCREL.
         */
        uint64_t pc = env->eip + (tb->cs_base & TB_CS_BASE_MASK);
        new_pc = (pc & TARGET_PAGE_MASK) | data[0];
    } else {
        new_pc = data[0];
    }
    if (tb->flags & HF_CS64_MASK) {
        env->eip = new_pc;
    } else {
        env->eip = (uint32_t)(new_pc - (tb->cs_base & TB_CS_BASE_MASK));
    }

    if (cc_op != CC_OP_DYNAMIC) {
        env->cc_op = cc_op;
    }
    env->svm_insn_len = data[2] & X86_PMU_INSN_LEN;
#ifndef CONFIG_USER_ONLY
    if (x86_pmu_enabled(env)) {
        x86_pmu_restore(env, tb, data[2]);
    }
    /* Of the PAUSE filter's cycles, those of the instructions not retired. */
    if (tb->flags & HF_PAUSE_COUNT_MASK) {
        env->svm_pause_cycles -=
            tb->icount - (data[2] >> X86_PMU_INSN_INDEX_SHIFT);
    }
#endif
}

int x86_mmu_index_pl(CPUX86State *env, unsigned pl)
{
    int mmu_index_32 = (env->hflags & HF_CS64_MASK) ? 0 : 1;
    int mmu_index_base =
        pl == 3 ? MMU_USER64_IDX :
        !(env->hflags & HF_SMAP_MASK) ? MMU_KNOSMAP64_IDX :
        (env->eflags & AC_MASK) ? MMU_KNOSMAP64_IDX : MMU_KSMAP64_IDX;
    return mmu_index_base + mmu_index_32 + x86_mmu_offset(env);
}

static int x86_cpu_mmu_index(CPUState *cs, bool ifetch)
{
    CPUX86State *env = cpu_env(cs);
    return x86_mmu_index_pl(env, env->hflags & HF_CPL_MASK);
}

#ifndef CONFIG_USER_ONLY
static bool x86_debug_check_breakpoint(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    /*
     * RF disables all architectural breakpoints, and on Intel processors
     * MOV SS and POP SS the instruction breakpoints of the next instruction
     * (Intel SDM 325462-093 Vol. 3A, 7.8.3).
     */
    return !(env->eflags & RF_MASK) &&
           !(IS_INTEL_CPU(env) && (env->hflags & HF_INHIBIT_IRQ_MASK) &&
             env->shadow_movss);
}

static void x86_cpu_exec_reset(CPUState *cs)
{
    CPUArchState *env = cpu_env(cs);

    if (x86_vmx_holds_init(env)) {
        cpu_reset_interrupt(cs, CPU_INTERRUPT_INIT);
        return;
    }
    cpu_svm_check_intercept_param(env, SVM_EXIT_INIT, 0, 0);
    /*
     * A clear GIF holds INIT pending until it is set (AMD APM 24593 rev.
     * 3.45, 15.17, Table 15-10), as after the #VMEXIT that intercepts it.
     */
    if (!(env->hflags2 & HF2_GIF_MASK)) {
        env->svm_init_held = true;
        cpu_reset_interrupt(cs, CPU_INTERRUPT_INIT);
        return;
    }
    do_cpu_init(env_archcpu(env));
    cs->exception_index = EXCP_HALTED;
}

static vaddr x86_pointer_wrap(CPUState *cs, int mmu_idx,
                              vaddr result, vaddr base)
{
    return cpu_env(cs)->hflags & HF_CS64_MASK ? result : (uint32_t)result;
}
#endif

const TCGCPUOps x86_tcg_ops = {
    .mttcg_supported = true,
    .precise_smc = true,
    /*
     * The x86 has a strong memory model with some store-after-load re-ordering
     */
    .guest_default_memory_order = TCG_MO_ALL & ~TCG_MO_ST_LD,
    .initialize = tcg_x86_init,
    .translate_code = x86_translate_code,
    .get_tb_cpu_state = x86_get_tb_cpu_state,
    .synchronize_from_tb = x86_cpu_synchronize_from_tb,
    .restore_state_to_opc = x86_restore_state_to_opc,
    .mmu_index = x86_cpu_mmu_index,
    .cpu_exec_enter = x86_cpu_exec_enter,
    .cpu_exec_exit = x86_cpu_exec_exit,
#ifdef CONFIG_USER_ONLY
    .fake_user_interrupt = x86_cpu_do_interrupt,
    .record_sigsegv = x86_cpu_record_sigsegv,
    .record_sigbus = x86_cpu_record_sigbus,
#else
    .tlb_fill = x86_cpu_tlb_fill,
    .pointer_wrap = x86_pointer_wrap,
    .do_interrupt = x86_cpu_do_interrupt,
    .poll_during_halt = x86_cpu_poll_during_halt,
    .leaving_halt = x86_cpu_leaving_halt,
    .cpu_exec_interrupt = x86_cpu_exec_interrupt,
    .cpu_exec_reset = x86_cpu_exec_reset,
    .do_unaligned_access = x86_cpu_do_unaligned_access,
    .debug_excp_handler = breakpoint_handler,
    .debug_check_breakpoint = x86_debug_check_breakpoint,
    .debug_check_watchpoint = x86_debug_check_watchpoint,
    .need_replay_interrupt = x86_need_replay_interrupt,
#endif /* !CONFIG_USER_ONLY */
};

static void x86_tcg_cpu_xsave_init(void)
{
#define XO(bit, field) \
    x86_ext_save_areas[bit].offset = offsetof(X86XSaveArea, field);

    XO(XSTATE_FP_BIT, legacy);
    XO(XSTATE_SSE_BIT, legacy);
    XO(XSTATE_YMM_BIT, avx_state);
    XO(XSTATE_BNDREGS_BIT, mpx_state.bndreg);
    XO(XSTATE_BNDCSR_BIT, mpx_state.bndcsr);
    XO(XSTATE_OPMASK_BIT, opmask_state);
    XO(XSTATE_ZMM_Hi256_BIT, zmm_hi256_state);
    XO(XSTATE_Hi16_ZMM_BIT, hi16_zmm_state);
    XO(XSTATE_PKRU_BIT, pkru_state);
    XO(XSTATE_APX_BIT, apx_state);

#undef XO

    /*
     * CET state is supervisor state: IA32_XSS manages it and only the
     * compacted format holds it, so it has no offset of its own (Intel SDM
     * 325462-093 Vol. 1, 13.2 and 13.5.9).
     */
    x86_ext_save_areas[XSTATE_CET_U_BIT].ecx = ESA_FEATURE_XSS_MASK;
    x86_ext_save_areas[XSTATE_CET_S_BIT].ecx = ESA_FEATURE_XSS_MASK;
}

/*
 * TCG-specific defaults that override cpudef models when using TCG.
 * Only for builtin_x86_defs models initialized with x86_register_cpudef_types.
 */
static PropValue x86_tcg_default_props[] = {
    { "vme", "off" },
    { NULL, NULL },
};

static void x86_tcg_cpu_instance_init(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    X86CPUClass *xcc = X86_CPU_GET_CLASS(cpu);

    if (xcc->model) {
        /* Special cases not set in the X86CPUDefinition structs: */
        x86_cpu_apply_props(cpu, x86_tcg_default_props);
    }

    x86_tcg_cpu_xsave_init();
}

static void x86_tcg_cpu_accel_class_init(ObjectClass *oc, const void *data)
{
    AccelCPUClass *acc = ACCEL_CPU_CLASS(oc);

#ifndef CONFIG_USER_ONLY
    acc->cpu_target_realize = tcg_cpu_realizefn;
#endif /* CONFIG_USER_ONLY */

    acc->cpu_instance_init = x86_tcg_cpu_instance_init;
}
static const TypeInfo x86_tcg_cpu_accel_type_info = {
    .name = ACCEL_CPU_NAME("tcg"),

    .parent = TYPE_ACCEL_CPU,
    .class_init = x86_tcg_cpu_accel_class_init,
    .abstract = true,
};
static void x86_tcg_cpu_accel_register_types(void)
{
    type_register_static(&x86_tcg_cpu_accel_type_info);
}
type_init(x86_tcg_cpu_accel_register_types);
