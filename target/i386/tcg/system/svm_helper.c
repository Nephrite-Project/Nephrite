/*
 *  x86 SVM helpers (system only)
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
#include "qemu/log.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cputlb.h"
#include "accel/tcg/cpu-ldst.h"
#include "accel/tcg/cpu-loop.h"
#include "system/runstate.h"
#include "tcg/helper-tcg.h"

/* Secure Virtual Machine helpers */

/* Sets GIF; an INIT that the clear GIF held is pending again. */
static void svm_set_gif(CPUX86State *env)
{
    env->hflags2 |= HF2_GIF_MASK;
    if (env->svm_init_held) {
        env->svm_init_held = false;
        cpu_set_interrupt(env_cpu(env), CPU_INTERRUPT_INIT);
    }
}

static void svm_save_seg(CPUX86State *env, int mmu_idx, hwaddr addr,
                         const SegmentCache *sc)
{
    cpu_stw_le_mmuidx_ra(env, addr + offsetof(struct vmcb_seg, selector),
                      sc->selector, mmu_idx, 0);
    cpu_stq_le_mmuidx_ra(env, addr + offsetof(struct vmcb_seg, base),
                      sc->base, mmu_idx, 0);
    cpu_stl_le_mmuidx_ra(env, addr + offsetof(struct vmcb_seg, limit),
                      sc->limit, mmu_idx, 0);
    cpu_stw_le_mmuidx_ra(env, addr + offsetof(struct vmcb_seg, attrib),
                      ((sc->flags >> 8) & 0xff)
                      | ((sc->flags >> 12) & 0x0f00),
                      mmu_idx, 0);
}

/*
 * VMRUN and VMLOAD canonicalizes (i.e., sign-extend to bit 63) all base
 * addresses in the segment registers that have been loaded.
 */
static inline void svm_canonicalization(CPUX86State *env, target_ulong *seg_base)
{
    uint16_t shift_amt = 64 - cpu_x86_virtual_addr_width(env);
    *seg_base = (((int64_t) *seg_base) << shift_amt) >> shift_amt;
}

static void svm_load_seg(CPUX86State *env, int mmu_idx, hwaddr addr,
                         SegmentCache *sc)
{
    unsigned int flags;

    sc->selector =
        cpu_lduw_le_mmuidx_ra(env, addr + offsetof(struct vmcb_seg, selector),
                           mmu_idx, 0);
    sc->base =
        cpu_ldq_le_mmuidx_ra(env, addr + offsetof(struct vmcb_seg, base),
                          mmu_idx, 0);
    sc->limit =
        cpu_ldl_le_mmuidx_ra(env, addr + offsetof(struct vmcb_seg, limit),
                          mmu_idx, 0);
    flags =
        cpu_lduw_le_mmuidx_ra(env, addr + offsetof(struct vmcb_seg, attrib),
                           mmu_idx, 0);
    sc->flags = ((flags & 0xff) << 8) | ((flags & 0x0f00) << 12);

    svm_canonicalization(env, &sc->base);
}

static void svm_load_seg_cache(CPUX86State *env, int mmu_idx,
                               hwaddr addr, int seg_reg)
{
    SegmentCache sc;

    svm_load_seg(env, mmu_idx, addr, &sc);
    cpu_x86_load_seg_cache(env, seg_reg, sc.selector,
                           sc.base, sc.limit, sc.flags);
}

/* The segment registers of the VMCB's SEG group. */
static const struct {
    X86Seg reg;
    size_t offset;
} svm_cached_segs[] = {
    { R_ES, offsetof(struct vmcb, save.es) },
    { R_CS, offsetof(struct vmcb, save.cs) },
    { R_SS, offsetof(struct vmcb, save.ss) },
    { R_DS, offsetof(struct vmcb, save.ds) },
};

/*
 * The VMCB Clean field of the VMCB being run: its set bits let VMRUN take
 * those groups of guest state from the processor's cache of the VMCB last
 * run, if that is this one.
 */
static uint32_t svm_clean_bits(CPUX86State *env)
{
    SVMStateCache *c = &env->svm_cache;

    if (!(env->features[FEAT_SVM] & CPUID_SVM_VMCBCLEAN) ||
        !c->valid || c->vmcb != env->vm_vmcb) {
        return 0;
    }
    return x86_ldl_phys(env_cpu(env),
                        env->vm_vmcb + offsetof(struct vmcb, control.clean));
}

/*
 * With shadow stacks, VMRUN and #VMEXIT switch S_CET, SSP, and ISST_ADDR,
 * sign-extending the shadow-stack pointers, and VMRUN fails for an S_CET
 * with reserved bits set (AMD64 Architecture Programmer's Manual Volume 2,
 * 24593 rev. 3.45, 15.5.1 and Table B-2).
 */
static void svm_save_cet(CPUX86State *env, hwaddr addr)
{
    CPUState *cs = env_cpu(env);

    x86_stq_phys(cs, addr + offsetof(struct vmcb, save.s_cet), env->s_cet);
    x86_stq_phys(cs, addr + offsetof(struct vmcb, save.ssp), env->guest_ssp);
#ifdef TARGET_X86_64
    x86_stq_phys(cs, addr + offsetof(struct vmcb, save.isst_addr),
                 env->int_ssp_table);
#endif
}

static bool svm_load_cet(CPUX86State *env, hwaddr addr)
{
    CPUState *cs = env_cpu(env);
    uint64_t s_cet = x86_ldq_phys(cs, addr + offsetof(struct vmcb, save.s_cet));
    int i;

    if (!x86_cet_msr_valid(env, MSR_IA32_S_CET, s_cet)) {
        return false;
    }
    env->s_cet = s_cet;
    env->guest_ssp = x86_la_adjust(env, x86_ldq_phys(cs, addr +
                                   offsetof(struct vmcb, save.ssp)));
#ifdef TARGET_X86_64
    env->int_ssp_table = x86_la_adjust(env, x86_ldq_phys(cs, addr +
                                       offsetof(struct vmcb, save.isst_addr)));
#endif
    for (i = 0; i < 4; i++) {
        *x86_pl_ssp(env, i) = x86_la_adjust(env, *x86_pl_ssp(env, i));
    }
    return true;
}

/*
 * DebugCtl and the last branch MSRs, as LBR virtualization swaps them with
 * those of the save area at ADDR (AMD64 Architecture Programmer's Manual
 * Volume 2, 24593 rev. 3.45, 15.23.1).
 */
static void svm_store_lbr(CPUX86State *env, hwaddr addr)
{
    CPUState *cs = env_cpu(env);

    x86_stq_phys(cs, addr + offsetof(struct vmcb, save.dbgctl), env->debugctl);
    x86_stq_phys(cs, addr + offsetof(struct vmcb, save.br_from),
                 env->lbr_from);
    x86_stq_phys(cs, addr + offsetof(struct vmcb, save.br_to), env->lbr_to);
    x86_stq_phys(cs, addr + offsetof(struct vmcb, save.last_excp_from),
                 env->lbr_int_from);
    x86_stq_phys(cs, addr + offsetof(struct vmcb, save.last_excp_to),
                 env->lbr_int_to);
}

static void svm_load_lbr(CPUX86State *env, hwaddr addr)
{
    CPUState *cs = env_cpu(env);

    env->debugctl = x86_ldq_phys(cs, addr + offsetof(struct vmcb,
                                                     save.dbgctl)) &
                    (DEBUGCTL_LBR | DEBUGCTL_BTF);
    env->lbr_from = x86_ldq_phys(cs, addr + offsetof(struct vmcb,
                                                     save.br_from));
    env->lbr_to = x86_ldq_phys(cs, addr + offsetof(struct vmcb, save.br_to));
    env->lbr_int_from = x86_ldq_phys(cs, addr + offsetof(struct vmcb,
                                                         save.last_excp_from));
    env->lbr_int_to = x86_ldq_phys(cs, addr + offsetof(struct vmcb,
                                                       save.last_excp_to));
}

/*
 * AVIC, which needs nested paging, and x2AVIC, which needs AVIC, with
 * their pointers in the physical address width and a physical APIC ID
 * table of up to 256 entries for xAVIC, 512 for x2AVIC, else VMRUN fails
 * (AMD64 Architecture Programmer's Manual Volume 2, 24593 rev. 3.45,
 * 15.29.4).
 */
static void svm_vmrun_avic(CPUX86State *env, SVMStateCache *c,
                           uint32_t clean, uintptr_t retaddr)
{
    CPUState *cs = env_cpu(env);
    uint64_t high = ~MAKE_64BIT_MASK(0, env_archcpu(env)->phys_bits);

    env->svm_avic = (env->features[FEAT_SVM] & CPUID_SVM_AVIC) &&
                    (env->int_ctl & AVIC_ENABLE_MASK);
    env->svm_x2avic = (env->features[FEAT_SVM] & CPUID_SVM_X2AVIC) &&
                      (env->int_ctl & X2AVIC_ENABLE_MASK);
    if (env->svm_x2avic && !env->svm_avic) {
        cpu_vmexit(env, SVM_EXIT_ERR, 0, retaddr);
    }
    /*
     * The processor may cache the group at any VMRUN, AVIC on or not, so
     * a VMM that wrote it before turning AVIC on leaves it clean.
     */
    if (!(clean & SVM_CLEAN_AVIC)) {
        c->avic_vapic_bar =
            x86_ldq_phys(cs, env->vm_vmcb +
                         offsetof(struct vmcb, control.avic_vapic_bar));
        c->avic_backing_page =
            x86_ldq_phys(cs, env->vm_vmcb +
                         offsetof(struct vmcb, control.avic_backing_page));
        c->avic_logical_id =
            x86_ldq_phys(cs, env->vm_vmcb +
                         offsetof(struct vmcb, control.avic_logical_id));
        c->avic_physical_id =
            x86_ldq_phys(cs, env->vm_vmcb +
                         offsetof(struct vmcb, control.avic_physical_id));
    }
    if (!env->svm_avic) {
        return;
    }
    env->svm_avic_bar = c->avic_vapic_bar & ~0xfffULL;
    env->svm_avic_backing = c->avic_backing_page & ~0xfffULL;
    env->svm_avic_logical = c->avic_logical_id & ~0xfffULL;
    env->svm_avic_physical = c->avic_physical_id & ~0xfffULL;
    env->svm_avic_max_index = c->avic_physical_id & 0xfff;
    if (!(env->hflags2 & HF2_NPT_MASK) ||
        ((env->svm_avic_bar | env->svm_avic_backing | env->svm_avic_logical |
          env->svm_avic_physical) & high) ||
        env->svm_avic_max_index > (env->svm_x2avic ? 511 : 255)) {
        cpu_vmexit(env, SVM_EXIT_ERR, 0, retaddr);
    }
}

/* The guest's DebugCtl and last branch MSRs, which the cache now holds. */
static void svm_cache_lbr(CPUX86State *env, SVMStateCache *c)
{
    c->dbgctl = env->debugctl;
    c->br_from = env->lbr_from;
    c->br_to = env->lbr_to;
    c->last_excp_from = env->lbr_int_from;
    c->last_excp_to = env->lbr_int_to;
}

/* A segment as #VMEXIT stores it and VMRUN would load it back. */
static void svm_cache_seg(CPUX86State *env, SegmentCache *dst,
                          const SegmentCache *src)
{
    unsigned int attrib = ((src->flags >> 8) & 0xff) |
                          ((src->flags >> 12) & 0x0f00);

    dst->selector = (uint16_t)src->selector;
    dst->base = src->base;
    svm_canonicalization(env, &dst->base);
    dst->limit = src->limit;
    dst->flags = ((attrib & 0xff) << 8) | ((attrib & 0x0f00) << 12);
}

/*
 * The CR4 bits that change what the TLB entries made under them hold, as
 * the processor applies them at each access instead.
 */
#define SVM_TLB_CR4_BITS \
    (CR4_SMEP_MASK | CR4_SMAP_MASK | CR4_LA57_MASK | CR4_PKE_MASK | \
     CR4_PKS_MASK)

/*
 * The guest's translations outlive #VMEXIT and VMRUN, tagged with its
 * ASID, until TLB_CONTROL or the guest drops them (AMD64 Architecture
 * Programmer's Manual Volume 2, 24593 rev. 3.45, 15.16.1). Guest mode's
 * MMU indexes hold those of one ASID, made under one CR4 protection,
 * nested paging mode, and xAVIC vAPIC base, as their entries hold what
 * those decided.
 */
static void svm_vmrun_tlb(CPUX86State *env, uint32_t asid)
{
    CPUState *cs = env_cpu(env);
    uint8_t tlb_ctl = x86_ldub_phys(cs, env->vm_vmcb +
                                    offsetof(struct vmcb, control.tlb_ctl));
    hwaddr avic_bar = env->svm_avic && !env->svm_x2avic ?
                      env->svm_avic_bar : (hwaddr)-1;
    bool flush_guest = asid != env->svm_tlb_asid ||
                       ((env->cr[4] ^ env->svm_tlb_cr4) & SVM_TLB_CR4_BITS) ||
                       env->nested_pg_mode != env->svm_tlb_nested_pg_mode ||
                       avic_bar != env->svm_tlb_avic_bar;

    switch (tlb_ctl) {
    case TLB_CONTROL_DO_NOTHING:
        break;
    case TLB_CONTROL_FLUSH_ASID:
    case TLB_CONTROL_FLUSH_ASID_LOCAL:
        if (env->features[FEAT_SVM] & CPUID_SVM_FLUSHASID) {
            flush_guest = true;
            break;
        }
        /* fall through */
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "VMRUN: reserved TLB_CONTROL 0x%02x\n",
                      tlb_ctl);
        /* fall through */
    case TLB_CONTROL_FLUSH_ALL_ASID:
        tlb_flush(cs);
        flush_guest = false;
        break;
    }
    if (flush_guest) {
        tlb_flush_by_mmuidx(cs, MMU_GUEST_IDX_MAP | 1 << MMU_NESTED_IDX |
                                1 << MMU_NESTED_SUP_IDX);
    }
    env->svm_tlb_asid = asid;
    env->svm_tlb_cr4 = env->cr[4];
    env->svm_tlb_nested_pg_mode = env->nested_pg_mode;
    env->svm_tlb_avic_bar = avic_bar;
}

static inline bool is_efer_invalid_state (CPUX86State *env)
{
    if (!(env->efer & MSR_EFER_SVME)) {
        return true;
    }

    if (env->efer & MSR_EFER_RESERVED) {
        return true;
    }

    if ((env->efer & (MSR_EFER_LMA | MSR_EFER_LME)) &&
            !(env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM)) {
        return true;
    }

    if ((env->efer & MSR_EFER_LME) && (env->cr[0] & CR0_PG_MASK)
                                && !(env->cr[4] & CR4_PAE_MASK)) {
        return true;
    }

    if ((env->efer & MSR_EFER_LME) && (env->cr[0] & CR0_PG_MASK)
                                && !(env->cr[0] & CR0_PE_MASK)) {
        return true;
    }

    if ((env->efer & MSR_EFER_LME) && (env->cr[0] & CR0_PG_MASK)
                                && (env->cr[4] & CR4_PAE_MASK)
                                && (env->segs[R_CS].flags & DESC_L_MASK)
                                && (env->segs[R_CS].flags & DESC_B_MASK)) {
        return true;
    }

    return false;
}

static inline bool virtual_gif_enabled(CPUX86State *env)
{
    if (likely(env->hflags & HF_GUEST_MASK)) {
        return (env->features[FEAT_SVM] & CPUID_SVM_VGIF)
                    && (env->int_ctl & V_GIF_ENABLED_MASK);
    }
    return false;
}

/*
 * Whether VMLOAD or VMSAVE, run in guest mode without its intercept, takes
 * RAX as a guest physical address, as VMSAVE and VMLOAD virtualization has
 * it where enabled, rather than as a host physical one. Enabled, it needs
 * nested paging and a hypervisor in 64-bit mode, else the instruction exits
 * as if intercepted (AMD64 Architecture Programmer's Manual Volume 2, 24593
 * rev. 3.45, 15.33.1).
 */
static bool virtual_vm_load_save_enabled(CPUX86State *env, uint64_t exit_code,
                                         uintptr_t retaddr)
{
    CPUState *cs = env_cpu(env);
    uint64_t lbr_ctl, host_efer;
    uint16_t host_cs_attrib;

    if (likely(!(env->hflags & HF_GUEST_MASK)) ||
        !(env->features[FEAT_SVM] & CPUID_SVM_V_VMSAVE_VMLOAD)) {
        return false;
    }
    lbr_ctl = x86_ldq_phys(cs, env->vm_vmcb +
                           offsetof(struct vmcb, control.lbr_ctl));
    if (!(lbr_ctl & V_VMLOAD_VMSAVE_ENABLED_MASK)) {
        return false;
    }
    host_efer = x86_ldq_phys(cs, env->vm_hsave +
                             offsetof(struct vmcb, save.efer));
    host_cs_attrib = x86_lduw_phys(cs, env->vm_hsave +
                                   offsetof(struct vmcb, save.cs.attrib));
    if (!(env->hflags2 & HF2_NPT_MASK) || !(host_efer & MSR_EFER_LMA) ||
        !(host_cs_attrib & (DESC_L_MASK >> 12))) {
        cpu_vmexit(env, exit_code, 0, retaddr);
    }
    return true;
}

static inline bool virtual_gif_set(CPUX86State *env)
{
    return !virtual_gif_enabled(env) || (env->int_ctl & V_GIF_MASK);
}

void HELPER(vmrun)(CPUX86State *env, int aflag, int next_eip_addend)
{
    CPUState *cs = env_cpu(env);
    X86CPU *cpu = env_archcpu(env);
    target_ulong addr;
    uint64_t nested_ctl;
    uint32_t event_inj;
    uint32_t asid;
    uint64_t new_cr0;
    uint64_t new_cr3;
    uint64_t new_cr4;
    uint64_t new_dr6;
    uint64_t new_dr7;
    SVMStateCache *c = &env->svm_cache;
    uint32_t clean;

    if (aflag == 2) {
        addr = env->regs[R_EAX];
    } else {
        addr = (uint32_t)env->regs[R_EAX];
    }

    /* Exceptions are checked before the intercept.  */
    if (addr & (0xfff | ((~0ULL) << env_archcpu(env)->phys_bits))) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }

    cpu_svm_check_intercept_param(env, SVM_EXIT_VMRUN, 0, GETPC());

    qemu_log_mask(CPU_LOG_TB_IN_ASM, "vmrun! " TARGET_FMT_lx "\n", addr);

    env->vm_vmcb = addr;
    env->db_movss = 0;

    /* save the current CPU state in the hsave page */
    x86_stq_phys(cs, env->vm_hsave + offsetof(struct vmcb, save.gdtr.base),
             env->gdt.base);
    x86_stl_phys(cs, env->vm_hsave + offsetof(struct vmcb, save.gdtr.limit),
             env->gdt.limit);

    x86_stq_phys(cs, env->vm_hsave + offsetof(struct vmcb, save.idtr.base),
             env->idt.base);
    x86_stl_phys(cs, env->vm_hsave + offsetof(struct vmcb, save.idtr.limit),
             env->idt.limit);

    x86_stq_phys(cs,
             env->vm_hsave + offsetof(struct vmcb, save.cr0), env->cr[0]);
    x86_stq_phys(cs,
             env->vm_hsave + offsetof(struct vmcb, save.cr2), env->cr[2]);
    x86_stq_phys(cs,
             env->vm_hsave + offsetof(struct vmcb, save.cr3), env->cr[3]);
    x86_stq_phys(cs,
             env->vm_hsave + offsetof(struct vmcb, save.cr4), env->cr[4]);
    x86_stq_phys(cs,
             env->vm_hsave + offsetof(struct vmcb, save.dr6), env->dr[6]);
    x86_stq_phys(cs,
             env->vm_hsave + offsetof(struct vmcb, save.dr7), env->dr[7]);

    x86_stq_phys(cs,
             env->vm_hsave + offsetof(struct vmcb, save.efer), env->efer);
    x86_stq_phys(cs,
             env->vm_hsave + offsetof(struct vmcb, save.rflags),
             cpu_compute_eflags(env));

    svm_save_seg(env, MMU_PHYS_IDX,
                 env->vm_hsave + offsetof(struct vmcb, save.es),
                 &env->segs[R_ES]);
    svm_save_seg(env, MMU_PHYS_IDX,
                 env->vm_hsave + offsetof(struct vmcb, save.cs),
                 &env->segs[R_CS]);
    svm_save_seg(env, MMU_PHYS_IDX,
                 env->vm_hsave + offsetof(struct vmcb, save.ss),
                 &env->segs[R_SS]);
    svm_save_seg(env, MMU_PHYS_IDX,
                 env->vm_hsave + offsetof(struct vmcb, save.ds),
                 &env->segs[R_DS]);

    x86_stq_phys(cs, env->vm_hsave + offsetof(struct vmcb, save.rip),
             env->eip + next_eip_addend);
    x86_stq_phys(cs,
             env->vm_hsave + offsetof(struct vmcb, save.rsp), env->regs[R_ESP]);
    x86_stq_phys(cs,
             env->vm_hsave + offsetof(struct vmcb, save.rax), env->regs[R_EAX]);
    if (x86_has_shstk(env)) {
        svm_save_cet(env, env->vm_hsave);
    }

    clean = svm_clean_bits(env);
    c->valid = false;

    /* load the interception bitmaps so we do not need to access the
       vmcb in svm mode */
    if (!(clean & SVM_CLEAN_I)) {
        c->intercept = x86_ldq_phys(cs, env->vm_vmcb +
                                    offsetof(struct vmcb, control.intercept));
        c->intercept_vec5 =
            x86_ldl_phys(cs, env->vm_vmcb +
                         offsetof(struct vmcb, control.intercept_vec5));
        c->intercept_cr_read =
            x86_lduw_phys(cs, env->vm_vmcb +
                          offsetof(struct vmcb, control.intercept_cr_read));
        c->intercept_cr_write =
            x86_lduw_phys(cs, env->vm_vmcb +
                          offsetof(struct vmcb, control.intercept_cr_write));
        c->intercept_dr_read =
            x86_lduw_phys(cs, env->vm_vmcb +
                          offsetof(struct vmcb, control.intercept_dr_read));
        c->intercept_dr_write =
            x86_lduw_phys(cs, env->vm_vmcb +
                          offsetof(struct vmcb, control.intercept_dr_write));
        c->intercept_exceptions =
            x86_ldl_phys(cs, env->vm_vmcb +
                         offsetof(struct vmcb, control.intercept_exceptions));
        c->tsc_offset = x86_ldq_phys(cs, env->vm_vmcb +
                                     offsetof(struct vmcb, control.tsc_offset));
        c->pause_filter_thresh =
            x86_lduw_phys(cs, env->vm_vmcb +
                          offsetof(struct vmcb, control.pause_filter_thresh));
        c->pause_filter_count =
            x86_lduw_phys(cs, env->vm_vmcb +
                          offsetof(struct vmcb, control.pause_filter_count));
    }
    env->svm_pause_filter_thresh = c->pause_filter_thresh;
    env->svm_pause_filter_count = c->pause_filter_count;
    env->svm_pause_count = c->pause_filter_count;
    env->svm_last_pause = 0;
    env->intercept = c->intercept;
    env->intercept_vec5 = c->intercept_vec5;
    env->intercept_cr_read = c->intercept_cr_read;
    env->intercept_cr_write = c->intercept_cr_write;
    env->intercept_dr_read = c->intercept_dr_read;
    env->intercept_dr_write = c->intercept_dr_write;
    env->intercept_exceptions = c->intercept_exceptions;

    env->hflags &= ~HF_INHIBIT_IRQ_MASK;
    if (x86_ldl_phys(cs, env->vm_vmcb +
                offsetof(struct vmcb, control.int_state)) &
                 SVM_INTERRUPT_SHADOW_MASK) {
        env->hflags |= HF_INHIBIT_IRQ_MASK;
    }

    nested_ctl = x86_ldq_phys(cs, env->vm_vmcb + offsetof(struct vmcb,
                                                          control.nested_ctl));
    if (!(clean & SVM_CLEAN_ASID)) {
        c->asid = x86_ldl_phys(cs, env->vm_vmcb +
                               offsetof(struct vmcb, control.asid));
    }
    asid = c->asid;

    if (!(clean & SVM_CLEAN_IOPM)) {
        c->msrpm_base_pa =
            x86_ldq_phys(cs, env->vm_vmcb +
                         offsetof(struct vmcb, control.msrpm_base_pa));
        c->iopm_base_pa =
            x86_ldq_phys(cs, env->vm_vmcb +
                         offsetof(struct vmcb, control.iopm_base_pa));
    }
    env->svm_msrpm_base = c->msrpm_base_pa & ~0xfffULL;
    env->svm_iopm_base = c->iopm_base_pa & ~0xfffULL;

    if (env->svm_msrpm_base >= (1ull << cpu->phys_bits) - SVM_MSRPM_SIZE) {
        cpu_vmexit(env, SVM_EXIT_ERR, 0, GETPC());
    }

    if (env->svm_iopm_base >= (1ull << cpu->phys_bits) - SVM_IOPM_SIZE) {
        cpu_vmexit(env, SVM_EXIT_ERR, 0, GETPC());
    }

    env->nested_pg_mode = 0;

    if (!cpu_svm_has_intercept(env, SVM_EXIT_VMRUN)) {
        cpu_vmexit(env, SVM_EXIT_ERR, 0, GETPC());
    }
    if (asid == 0) {
        cpu_vmexit(env, SVM_EXIT_ERR, 0, GETPC());
    }

    if (!(clean & SVM_CLEAN_NP)) {
        c->nested_cr3 = x86_ldq_phys(cs, env->vm_vmcb +
                                     offsetof(struct vmcb, control.nested_cr3));
    }
    if (nested_ctl & SVM_NPT_ENABLED) {
        env->nested_cr3 = c->nested_cr3;
        env->hflags2 |= HF2_NPT_MASK;

        env->nested_pg_mode = get_pg_mode(env) & PG_MODE_SVM_MASK;
        if (env->cr[4] & CR4_SMEP_MASK) {
            env->nested_pg_mode |= PG_MODE_NESTED_SMEP;
        }
        if ((nested_ctl & SVM_NPT_GMET) &&
            (env->features[FEAT_SVM] & CPUID_SVM_GMET)) {
            env->nested_pg_mode |= PG_MODE_GMET;
        }
        if ((nested_ctl & SVM_NPT_ROGPT) &&
            (env->features[FEAT_SVM] & CPUID_SVM_ROGPT)) {
            env->nested_pg_mode |= PG_MODE_ROGPT;
        }
        if ((nested_ctl & SVM_NPT_PML) &&
            (env->features[FEAT_8000_000A_ECX] & CPUID_SVM_ECX_PML)) {
            env->nested_pg_mode |= PG_MODE_PML;
        }
    }
    /*
     * Without TlbiCtl, guests may always run INVLPGB and TLBSYNC (AMD64
     * Architecture Programmer's Manual Volume 2, 24593 rev. 3.45, Table B-1).
     */
    env->svm_tlbi_enabled = !(env->features[FEAT_SVM] & CPUID_SVM_TLBICTL) ||
                            (nested_ctl & SVM_NPT_TLBI);

    /* enable intercepts */
    env->hflags |= HF_GUEST_MASK;

    env->tsc_offset = c->tsc_offset;

    if (!(clean & SVM_CLEAN_CRX)) {
        c->cr0 = x86_ldq_phys(cs, env->vm_vmcb +
                              offsetof(struct vmcb, save.cr0));
        c->cr3 = x86_ldq_phys(cs, env->vm_vmcb +
                              offsetof(struct vmcb, save.cr3));
        c->cr4 = x86_ldq_phys(cs, env->vm_vmcb +
                              offsetof(struct vmcb, save.cr4));
        c->efer = x86_ldq_phys(cs, env->vm_vmcb +
                               offsetof(struct vmcb, save.efer));
    }
    new_cr0 = c->cr0;
    if (new_cr0 & SVM_CR0_RESERVED_MASK) {
        cpu_vmexit(env, SVM_EXIT_ERR, 0, GETPC());
    }
    if ((new_cr0 & CR0_NW_MASK) && !(new_cr0 & CR0_CD_MASK)) {
        cpu_vmexit(env, SVM_EXIT_ERR, 0, GETPC());
    }
    new_cr3 = c->cr3;
    if ((env->efer & MSR_EFER_LMA) &&
            (new_cr3 & ((~0ULL) << cpu->phys_bits))) {
        cpu_vmexit(env, SVM_EXIT_ERR, 0, GETPC());
    }
    new_cr4 = c->cr4;
    if (new_cr4 & cr4_reserved_bits(env)) {
        cpu_vmexit(env, SVM_EXIT_ERR, 0, GETPC());
    }
    /* clear exit_info_2 so we behave like the real hardware */
    x86_stq_phys(cs,
             env->vm_vmcb + offsetof(struct vmcb, control.exit_info_2), 0);

    env->svm_loading_crs = true;
    cpu_x86_update_cr0(env, new_cr0);
    cpu_x86_update_cr4(env, new_cr4);
    cpu_x86_update_cr3(env, new_cr3);
    env->svm_loading_crs = false;
    if (!(clean & SVM_CLEAN_CR2)) {
        c->cr2 = x86_ldq_phys(cs, env->vm_vmcb +
                              offsetof(struct vmcb, save.cr2));
    }
    env->cr[2] = c->cr2;
    if (!(clean & SVM_CLEAN_TPR)) {
        c->int_ctl = x86_ldl_phys(cs, env->vm_vmcb +
                                  offsetof(struct vmcb, control.int_ctl));
        c->int_vector = x86_ldl_phys(cs, env->vm_vmcb +
                                     offsetof(struct vmcb, control.int_vector));
    }
    env->int_ctl = c->int_ctl;
    env->svm_int_vector = c->int_vector;
    /*
     * Virtual NMIs need the NMI intercept (AMD64 Architecture Programmer's
     * Manual Volume 2, 24593 rev. 3.45, 15.21.10).
     */
    if (svm_vnmi_enabled(env) && !cpu_svm_has_intercept(env, SVM_EXIT_NMI)) {
        cpu_vmexit(env, SVM_EXIT_ERR, 0, GETPC());
    }
    svm_vmrun_avic(env, c, clean, GETPC());
    env->hflags2 &= ~(HF2_HIF_MASK | HF2_VINTR_MASK);
    if (env->int_ctl & V_INTR_MASKING_MASK) {
        env->hflags2 |= HF2_VINTR_MASK;
        if (env->eflags & IF_MASK) {
            env->hflags2 |= HF2_HIF_MASK;
        }
    }

    cpu_load_efer(env, c->efer);
    env->eflags = 0;
    cpu_load_eflags(env, x86_ldq_phys(cs,
                                  env->vm_vmcb + offsetof(struct vmcb,
                                                          save.rflags)),
                    ~(CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C | DF_MASK));

    for (int i = 0; i < ARRAY_SIZE(svm_cached_segs); i++) {
        SegmentCache *sc = &c->segs[i];

        if (!(clean & SVM_CLEAN_SEG)) {
            svm_load_seg(env, MMU_PHYS_IDX,
                         env->vm_vmcb + svm_cached_segs[i].offset, sc);
        }
        cpu_x86_load_seg_cache(env, svm_cached_segs[i].reg, sc->selector,
                               sc->base, sc->limit, sc->flags);
    }
    if (!(clean & SVM_CLEAN_DT)) {
        svm_load_seg(env, MMU_PHYS_IDX,
                     env->vm_vmcb + offsetof(struct vmcb, save.idtr), &c->idt);
        svm_load_seg(env, MMU_PHYS_IDX,
                     env->vm_vmcb + offsetof(struct vmcb, save.gdtr), &c->gdt);
    }
    env->idt = c->idt;
    env->gdt = c->gdt;

    env->eip = x86_ldq_phys(cs,
                        env->vm_vmcb + offsetof(struct vmcb, save.rip));

    env->regs[R_ESP] = x86_ldq_phys(cs,
                                env->vm_vmcb + offsetof(struct vmcb, save.rsp));
    env->regs[R_EAX] = x86_ldq_phys(cs,
                                env->vm_vmcb + offsetof(struct vmcb, save.rax));
    if (x86_has_shstk(env) && !svm_load_cet(env, env->vm_vmcb)) {
        cpu_vmexit(env, SVM_EXIT_ERR, 0, GETPC());
    }
    if ((env->cr[4] & CR4_CET_MASK) &&
        (!(env->cr[0] & CR0_WP_MASK) ||
         ((env->eflags & VM_MASK) && (env->u_cet & CET_SH_STK_EN)))) {
        cpu_vmexit(env, SVM_EXIT_ERR, 0, GETPC());
    }

    if (!(clean & SVM_CLEAN_DRX)) {
        c->dr7 = x86_ldq_phys(cs, env->vm_vmcb +
                              offsetof(struct vmcb, save.dr7));
        c->dr6 = x86_ldq_phys(cs, env->vm_vmcb +
                              offsetof(struct vmcb, save.dr6));
    }
    new_dr7 = c->dr7;
    new_dr6 = c->dr6;

#ifdef TARGET_X86_64
    if (new_dr7 & DR_RESERVED_MASK) {
        cpu_vmexit(env, SVM_EXIT_ERR, 0, GETPC());
    }
    if (new_dr6 & DR_RESERVED_MASK) {
        cpu_vmexit(env, SVM_EXIT_ERR, 0, GETPC());
    }
#endif

    cpu_x86_update_dr7(env, new_dr7);
    env->dr[6] = new_dr6;

    if (is_efer_invalid_state(env)) {
        cpu_vmexit(env, SVM_EXIT_ERR, 0, GETPC());
    }
    /*
     * A guest with PAE paging gets, without nested paging, the PDPEs at its
     * CR3 for the PDPTE registers, where reserved bits make VMRUN fail (AMD64
     * Architecture Programmer's Manual Volume 2, 24593 rev. 3.45, 15.5.1).
     */
    if (!(env->hflags2 & HF2_NPT_MASK) &&
        x86_pae_paging(env->cr[0], env->cr[4], env->efer) &&
        !x86_load_pdptes(env)) {
        cpu_vmexit(env, SVM_EXIT_ERR, 0, GETPC());
    }

    if ((env->features[FEAT_SVM] & CPUID_SVM_LBRV) &&
        (x86_ldq_phys(cs, env->vm_vmcb + offsetof(struct vmcb,
                                                  control.lbr_ctl)) &
         LBR_CTL_ENABLE_MASK)) {
        svm_store_lbr(env, env->vm_hsave);
        if ((clean & SVM_CLEAN_LBR) && c->lbr_virt) {
            env->debugctl = c->dbgctl;
            env->lbr_from = c->br_from;
            env->lbr_to = c->br_to;
            env->lbr_int_from = c->last_excp_from;
            env->lbr_int_to = c->last_excp_to;
        } else {
            svm_load_lbr(env, env->vm_vmcb);
            svm_cache_lbr(env, c);
        }
        env->svm_lbr_virt = true;
    }
    c->lbr_virt = env->svm_lbr_virt;

    /* The guest state just loaded is what the processor now caches. */
    c->vmcb = env->vm_vmcb;
    c->valid = true;

    svm_vmrun_tlb(env, asid);

    svm_set_gif(env);

    /* AVIC looks at the backing page upon entry into the guest. */
    if (env->svm_avic) {
        svm_avic_request(env);
    } else if (ctl_has_irq(env)) {
        cpu_set_interrupt(cs, CPU_INTERRUPT_VIRQ);
    }
    if (svm_vnmi_enabled(env) && (env->int_ctl & V_NMI_PENDING_MASK)) {
        cpu_set_interrupt(cs, CPU_INTERRUPT_VNMI);
    }

    if (virtual_gif_set(env)) {
        env->hflags2 |= HF2_VGIF_MASK;
    }

    /* maybe we need to inject an event */
    event_inj = x86_ldl_phys(cs, env->vm_vmcb + offsetof(struct vmcb,
                                                 control.event_inj));
    if (event_inj & SVM_EVTINJ_VALID) {
        uint8_t vector = event_inj & SVM_EVTINJ_VEC_MASK;
        uint16_t valid_err = event_inj & SVM_EVTINJ_VALID_ERR;
        uint32_t event_inj_err = x86_ldl_phys(cs, env->vm_vmcb +
                                          offsetof(struct vmcb,
                                                   control.event_inj_err));

        /*
         * With NRIPS, software interrupts and the traps of INT3 and INTO
         * return to the next RIP the VMCB gives (AMD64 Architecture
         * Programmer's Manual Volume 2, 24593 rev. 3.45, 15.20); without
         * it, to the guest's RIP.
         */
        target_ulong next_eip = env->eip;

        if (env->features[FEAT_SVM] & CPUID_SVM_NRIPSAVE) {
            next_eip = x86_ldq_phys(cs, env->vm_vmcb +
                                    offsetof(struct vmcb, control.next_rip));
        }

        qemu_log_mask(CPU_LOG_TB_IN_ASM, "Injecting(%#hx): ", valid_err);
        /* FIXME: need to implement valid_err */
        switch (event_inj & SVM_EVTINJ_TYPE_MASK) {
        case SVM_EVTINJ_TYPE_INTR:
            cs->exception_index = vector;
            env->error_code = event_inj_err;
            env->exception_is_int = 0;
            env->exception_next_eip = -1;
            qemu_log_mask(CPU_LOG_TB_IN_ASM, "INTR");
            /* XXX: is it always correct? */
            do_interrupt_x86_hardirq(env, vector, 1);
            /*
             * Delivered: an exception index left set would be delivered
             * again, as an exception, at the vCPU's next kick.
             */
            cs->exception_index = -1;
            break;
        case SVM_EVTINJ_TYPE_NMI:
            /* An injected NMI blocks virtual ones, as a virtual NMI does. */
            if (svm_vnmi_enabled(env)) {
                env->int_ctl |= V_NMI_BLOCKING_MASK;
            }
            cs->exception_index = EXCP02_NMI;
            env->error_code = event_inj_err;
            env->exception_is_int = 0;
            env->exception_next_eip = env->eip;
            qemu_log_mask(CPU_LOG_TB_IN_ASM, "NMI");
            cpu_loop_exit(cs);
            break;
        case SVM_EVTINJ_TYPE_EXEPT:
            if (vector == EXCP02_NMI || vector >= 31)  {
                cpu_vmexit(env, SVM_EXIT_ERR, 0, GETPC());
            }
            cs->exception_index = vector;
            env->error_code = event_inj_err;
            /*
             * Vectors 3 and 4 are the traps of INT3 and INTO, with their
             * privilege checks.
             */
            if (vector == EXCP03_INT3 || vector == EXCP04_INTO) {
                env->exception_is_int = 1;
                env->exception_next_eip = next_eip;
            } else {
                env->exception_is_int = 0;
                env->exception_next_eip = -1;
            }
            qemu_log_mask(CPU_LOG_TB_IN_ASM, "EXEPT");
            cpu_loop_exit(cs);
            break;
        case SVM_EVTINJ_TYPE_SOFT:
            cs->exception_index = vector;
            env->error_code = event_inj_err;
            env->exception_is_int = 1;
            env->exception_next_eip = next_eip;
            qemu_log_mask(CPU_LOG_TB_IN_ASM, "SOFT");
            cpu_loop_exit(cs);
            break;
        default:
            cpu_vmexit(env, SVM_EXIT_ERR, 0, GETPC());
            break;
        }
        qemu_log_mask(CPU_LOG_TB_IN_ASM, " %#x %#x\n", cs->exception_index,
                      env->error_code);
    }
}

void HELPER(vmmcall)(CPUX86State *env)
{
    cpu_svm_check_intercept_param(env, SVM_EXIT_VMMCALL, 0, GETPC());
    raise_exception_ra(env, EXCP06_ILLOP, GETPC());
}

void HELPER(vmload)(CPUX86State *env, int aflag)
{
    int mmu_idx = MMU_PHYS_IDX;
    target_ulong addr;

    if (aflag == 2) {
        addr = env->regs[R_EAX];
    } else {
        addr = (uint32_t)env->regs[R_EAX];
    }

    /* Exceptions are checked before the intercept.  */
    if (addr & (0xfff | ((~0ULL) << env_archcpu(env)->phys_bits))) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }

    cpu_svm_check_intercept_param(env, SVM_EXIT_VMLOAD, 0, GETPC());

    if (virtual_vm_load_save_enabled(env, SVM_EXIT_VMLOAD, GETPC())) {
        mmu_idx = MMU_NESTED_IDX;
    }

    svm_load_seg_cache(env, mmu_idx,
                       addr + offsetof(struct vmcb, save.fs), R_FS);
    svm_load_seg_cache(env, mmu_idx,
                       addr + offsetof(struct vmcb, save.gs), R_GS);
    svm_load_seg(env, mmu_idx,
                 addr + offsetof(struct vmcb, save.tr), &env->tr);
    svm_load_seg(env, mmu_idx,
                 addr + offsetof(struct vmcb, save.ldtr), &env->ldt);

#ifdef TARGET_X86_64
    env->kernelgsbase =
        cpu_ldq_le_mmuidx_ra(env,
                             addr + offsetof(struct vmcb, save.kernel_gs_base),
                             mmu_idx, 0);
    env->lstar =
        cpu_ldq_le_mmuidx_ra(env, addr + offsetof(struct vmcb, save.lstar),
                             mmu_idx, 0);
    env->cstar =
        cpu_ldq_le_mmuidx_ra(env, addr + offsetof(struct vmcb, save.cstar),
                             mmu_idx, 0);
    env->fmask =
        cpu_ldq_le_mmuidx_ra(env, addr + offsetof(struct vmcb, save.sfmask),
                             mmu_idx, 0);
    svm_canonicalization(env, &env->kernelgsbase);
#endif
    env->star =
        cpu_ldq_le_mmuidx_ra(env, addr + offsetof(struct vmcb, save.star),
                             mmu_idx, 0);
    env->sysenter_cs =
        cpu_ldq_le_mmuidx_ra(env,
                             addr + offsetof(struct vmcb, save.sysenter_cs),
                             mmu_idx, 0);
    env->sysenter_esp =
        cpu_ldq_le_mmuidx_ra(env,
                             addr + offsetof(struct vmcb, save.sysenter_esp),
                             mmu_idx, 0);
    env->sysenter_eip =
        cpu_ldq_le_mmuidx_ra(env,
                             addr + offsetof(struct vmcb, save.sysenter_eip),
                             mmu_idx, 0);
}

void HELPER(vmsave)(CPUX86State *env, int aflag)
{
    int mmu_idx = MMU_PHYS_IDX;
    target_ulong addr;

    if (aflag == 2) {
        addr = env->regs[R_EAX];
    } else {
        addr = (uint32_t)env->regs[R_EAX];
    }

    /* Exceptions are checked before the intercept.  */
    if (addr & (0xfff | ((~0ULL) << env_archcpu(env)->phys_bits))) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }

    cpu_svm_check_intercept_param(env, SVM_EXIT_VMSAVE, 0, GETPC());

    if (virtual_vm_load_save_enabled(env, SVM_EXIT_VMSAVE, GETPC())) {
        mmu_idx = MMU_NESTED_IDX;
    }

    svm_save_seg(env, mmu_idx, addr + offsetof(struct vmcb, save.fs),
                 &env->segs[R_FS]);
    svm_save_seg(env, mmu_idx, addr + offsetof(struct vmcb, save.gs),
                 &env->segs[R_GS]);
    svm_save_seg(env, mmu_idx, addr + offsetof(struct vmcb, save.tr),
                 &env->tr);
    svm_save_seg(env, mmu_idx, addr + offsetof(struct vmcb, save.ldtr),
                 &env->ldt);

#ifdef TARGET_X86_64
    cpu_stq_le_mmuidx_ra(env, addr + offsetof(struct vmcb, save.kernel_gs_base),
                      env->kernelgsbase, mmu_idx, 0);
    cpu_stq_le_mmuidx_ra(env, addr + offsetof(struct vmcb, save.lstar),
                      env->lstar, mmu_idx, 0);
    cpu_stq_le_mmuidx_ra(env, addr + offsetof(struct vmcb, save.cstar),
                      env->cstar, mmu_idx, 0);
    cpu_stq_le_mmuidx_ra(env, addr + offsetof(struct vmcb, save.sfmask),
                      env->fmask, mmu_idx, 0);
#endif
    cpu_stq_le_mmuidx_ra(env, addr + offsetof(struct vmcb, save.star),
                      env->star, mmu_idx, 0);
    cpu_stq_le_mmuidx_ra(env, addr + offsetof(struct vmcb, save.sysenter_cs),
                      env->sysenter_cs, mmu_idx, 0);
    cpu_stq_le_mmuidx_ra(env, addr + offsetof(struct vmcb, save.sysenter_esp),
                      env->sysenter_esp, mmu_idx, 0);
    cpu_stq_le_mmuidx_ra(env, addr + offsetof(struct vmcb, save.sysenter_eip),
                      env->sysenter_eip, mmu_idx, 0);
}

void HELPER(stgi)(CPUX86State *env)
{
    cpu_svm_check_intercept_param(env, SVM_EXIT_STGI, 0, GETPC());

    if (virtual_gif_enabled(env)) {
        env->int_ctl |= V_GIF_MASK;
        env->hflags2 |= HF2_VGIF_MASK;
    } else {
        svm_set_gif(env);
    }
}

void HELPER(clgi)(CPUX86State *env)
{
    cpu_svm_check_intercept_param(env, SVM_EXIT_CLGI, 0, GETPC());

    if (virtual_gif_enabled(env)) {
        env->int_ctl &= ~V_GIF_MASK;
        env->hflags2 &= ~HF2_VGIF_MASK;
    } else {
        env->hflags2 &= ~HF2_GIF_MASK;
    }
}

bool cpu_svm_has_intercept(CPUX86State *env, uint32_t type)
{
    if (env->vmx.nonroot) {
        return false;
    }
    switch (type) {
    case SVM_EXIT_READ_CR0 ... SVM_EXIT_READ_CR0 + 8:
        if (env->intercept_cr_read & (1 << (type - SVM_EXIT_READ_CR0))) {
            return true;
        }
        break;
    case SVM_EXIT_WRITE_CR0 ... SVM_EXIT_WRITE_CR0 + 8:
        if (env->intercept_cr_write & (1 << (type - SVM_EXIT_WRITE_CR0))) {
            return true;
        }
        break;
    case SVM_EXIT_READ_DR0 ... SVM_EXIT_READ_DR0 + 7:
        if (env->intercept_dr_read & (1 << (type - SVM_EXIT_READ_DR0))) {
            return true;
        }
        break;
    case SVM_EXIT_WRITE_DR0 ... SVM_EXIT_WRITE_DR0 + 7:
        if (env->intercept_dr_write & (1 << (type - SVM_EXIT_WRITE_DR0))) {
            return true;
        }
        break;
    case SVM_EXIT_EXCP_BASE ... SVM_EXIT_EXCP_BASE + 31:
        if (env->intercept_exceptions & (1 << (type - SVM_EXIT_EXCP_BASE))) {
            return true;
        }
        break;
    case SVM_EXIT_INVLPGB ... SVM_EXIT_IDLE_HLT:
        if (env->intercept_vec5 & (1 << (type - SVM_EXIT_INVLPGB))) {
            return true;
        }
        break;
    default:
        if (env->intercept & (1ULL << (type - SVM_EXIT_INTR))) {
            return true;
        }
        break;
    }
    return false;
}

/*
 * Whether an intercepted PAUSE exits, by the PAUSE filter: VMRUN loads its
 * count, which each PAUSE lowers, exiting where it reaches zero; with a
 * threshold, a PAUSE more cycles than that after the last one reloads the
 * count first, and the exit comes where it falls below zero (AMD64
 * Architecture Programmer's Manual Volume 2, 24593 rev. 3.45, 15.14.4).
 */
static bool svm_pause_exits(CPUX86State *env)
{
    uint64_t now;

    if (!(env->features[FEAT_SVM] & CPUID_SVM_PAUSEFILTER)) {
        return true;
    }
    if (!(env->features[FEAT_SVM] & CPUID_SVM_PFTHRESHOLD) ||
        !env->svm_pause_filter_thresh) {
        return --env->svm_pause_count <= 0;
    }
    now = cpu_get_tsc(env);
    if (now - env->svm_last_pause > env->svm_pause_filter_thresh) {
        env->svm_pause_count = env->svm_pause_filter_count;
    }
    env->svm_last_pause = now;
    return --env->svm_pause_count < 0;
}

void cpu_svm_check_intercept_param(CPUX86State *env, uint32_t type,
                                   uint64_t param, uintptr_t retaddr)
{
    CPUState *cs = env_cpu(env);

    if (likely(!(env->hflags & HF_GUEST_MASK))) {
        return;
    }
    if (env->vmx.nonroot) {
        x86_vmx_check_intercept(env, type, param, retaddr);
        return;
    }

    if (!cpu_svm_has_intercept(env, type)) {
        return;
    }

    if (type == SVM_EXIT_MSR) {
        uint64_t addr = env->svm_msrpm_base;
        uint32_t t0, t1;

        switch ((uint32_t)env->regs[R_ECX]) {
        case 0 ... 0x1fff:
            t0 = (env->regs[R_ECX] * 2) % 8;
            t1 = (env->regs[R_ECX] * 2) / 8;
            break;
        case 0xc0000000 ... 0xc0001fff:
            t0 = (8192 + env->regs[R_ECX] - 0xc0000000) * 2;
            t1 = (t0 / 8);
            t0 %= 8;
            break;
        case 0xc0010000 ... 0xc0011fff:
            t0 = (16384 + env->regs[R_ECX] - 0xc0010000) * 2;
            t1 = (t0 / 8);
            t0 %= 8;
            break;
        default:
            cpu_vmexit(env, type, param, retaddr);
            t0 = 0;
            t1 = 0;
            break;
        }
        if (x86_ldub_phys(cs, addr + t1) & ((1 << param) << t0)) {
            cpu_vmexit(env, type, param, retaddr);
        }
        return;
    }

    if (type == SVM_EXIT_PAUSE && !svm_pause_exits(env)) {
        return;
    }

    cpu_vmexit(env, type, param, retaddr);
}

/*
 * With decode assists, info is EXITINFO1 of the instruction's intercept: for
 * MOV to or from a CR, the GPR number and bit 63, for MOV to or from a DR the
 * GPR number, and for INVLPG the linear address (AMD64 Architecture
 * Programmer's Manual Volume 2, 24593 rev. 3.45, 15.8). write_crN takes it
 * for the selective CR0 write intercept.
 */
void HELPER(svm_check_intercept)(CPUX86State *env, uint32_t type,
                                 uint64_t info)
{
    if (!(env->features[FEAT_SVM] & CPUID_SVM_DECODEASSIST) &&
        !env->vmx.nonroot) {
        info = 0;
    }
    env->svm_decode_info = info;
    cpu_svm_check_intercept_param(env, type, info, GETPC());
}

/*
 * MOV to a CR and MOV DR take SVM's intercept after their other exception
 * checks (AMD64 Architecture Programmer's Manual Volume 2, 24593 rev. 3.45,
 * Table 15-7), through x86_svm_late_intercept(), but VMX's MOV-DR exit
 * before those and the privilege check (Intel SDM 325462-093 Vol. 3C,
 * 28.1.3). The decode-assist information waits for either.
 */
void HELPER(mov_crdr_intercept)(CPUX86State *env, uint32_t type,
                                uint64_t info)
{
    if (!(env->features[FEAT_SVM] & CPUID_SVM_DECODEASSIST) &&
        !env->vmx.nonroot) {
        info = 0;
    }
    env->svm_decode_info = info;
    if (env->vmx.nonroot && type >= SVM_EXIT_READ_DR0) {
        cpu_svm_check_intercept_param(env, type, info, GETPC());
    }
}

void x86_svm_late_intercept(CPUX86State *env, uint32_t type, uintptr_t ra)
{
    if (!env->vmx.nonroot) {
        cpu_svm_check_intercept_param(env, type, env->svm_decode_info, ra);
    }
}

void HELPER(svm_check_io)(CPUX86State *env, uint32_t port, uint32_t param,
                         uint32_t next_eip_addend)
{
    CPUState *cs = env_cpu(env);

    if (env->vmx.nonroot) {
        x86_vmx_check_io(env, port, param, GETPC());
        return;
    }
    param &= ~SVM_IOIO_IMM_MASK;
    if (!(env->features[FEAT_SVM] & CPUID_SVM_DECODEASSIST)) {
        param &= ~(7 << SVM_IOIO_SEG_SHIFT);
    }
    if (env->intercept & (1ULL << (SVM_EXIT_IOIO - SVM_EXIT_INTR))) {
        uint64_t addr = env->svm_iopm_base;
        uint16_t mask = (1 << ((param >> 4) & 7)) - 1;

        if (x86_lduw_phys(cs, addr + port / 8) & (mask << (port & 7))) {
            /* next env->eip */
            x86_stq_phys(cs,
                     env->vm_vmcb + offsetof(struct vmcb, control.exit_info_2),
                     env->eip + next_eip_addend);
            cpu_vmexit(env, SVM_EXIT_IOIO, param | (port << 16), GETPC());
        }
    }
}

/*
 * The intercepts that save the next sequential RIP: those of instructions,
 * MSR and IOIO accesses, and the exceptions INT3, INTO, and BOUND raise
 * (AMD64 Architecture Programmer's Manual Volume 2, 24593 rev. 3.45, 15.7.1).
 */
static bool svm_exit_saves_next_rip(uint64_t exit_code)
{
    switch (exit_code) {
    case SVM_EXIT_READ_CR0 ... SVM_EXIT_WRITE_DR0 + 15:
    case SVM_EXIT_EXCP_BASE + EXCP03_INT3:
    case SVM_EXIT_EXCP_BASE + EXCP04_INTO:
    case SVM_EXIT_EXCP_BASE + EXCP05_BOUND:
    case SVM_EXIT_CR0_SEL_WRITE ... SVM_EXIT_MSR:
    case SVM_EXIT_VMRUN ... SVM_EXIT_RDPRU:
    case SVM_EXIT_INVLPGB ... SVM_EXIT_TLBSYNC:
    case SVM_EXIT_IDLE_HLT:
        return true;
    default:
        return false;
    }
}

/* The RIP a trap after the current instruction would push. */
target_ulong svm_next_rip(CPUX86State *env)
{
    target_ulong next = env->eip + env->svm_insn_len;

    if (env->hflags & HF_CS64_MASK) {
        return next;
    }
    return env->hflags & HF_CS32_MASK ? (uint32_t)next : (uint16_t)next;
}

void cpu_vmexit(CPUX86State *env, uint64_t exit_code, uint64_t exit_info_1,
                uintptr_t retaddr)
{
    CPUState *cs = env_cpu(env);

    /*
     * A failed VMRUN returns to the host after VMRUN without having run the
     * guest, whose state in the VMCB stays as the host wrote it: restoring
     * the state of VMRUN's own TB would make the host's RIP the guest's.
     */
    if (exit_code != SVM_EXIT_ERR) {
        cpu_restore_state(cs, retaddr);
    }

    if (env->features[FEAT_SVM] & CPUID_SVM_NRIPSAVE) {
        x86_stq_phys(cs,
                     env->vm_vmcb + offsetof(struct vmcb, control.next_rip),
                     svm_exit_saves_next_rip(exit_code) ?
                     svm_next_rip(env) : 0);
    }

    /*
     * Decode assists: the instruction bytes of nested and intercepted page
     * faults; all other intercepts clear their count.
     */
    if (env->features[FEAT_SVM] & CPUID_SVM_DECODEASSIST) {
        bool page_fault = exit_code == SVM_EXIT_NPF ||
                          exit_code == SVM_EXIT_EXCP_BASE + EXCP0E_PAGE;
        uint8_t count = page_fault && env->svm_insn_bytes_valid ?
                        env->svm_insn_fetched : 0;

        x86_stb_phys(cs, env->vm_vmcb + offsetof(struct vmcb, control.insn_len),
                     count);
        for (int i = 0; i < count; i++) {
            x86_stb_phys(cs, env->vm_vmcb +
                         offsetof(struct vmcb, control.insn_bytes) + i,
                         env->svm_insn_bytes[i]);
        }
        env->svm_insn_bytes_valid = false;
    }

    qemu_log_mask(CPU_LOG_TB_IN_ASM, "vmexit(%08x, %016" PRIx64 ", %016"
                  PRIx64 ", " TARGET_FMT_lx ")!\n",
                  (uint32_t)exit_code, exit_info_1,
                  x86_ldq_phys(cs, env->vm_vmcb + offsetof(struct vmcb,
                                                   control.exit_info_2)),
                  env->eip);

    cs->exception_index = EXCP_VMEXIT;
    x86_stq_phys(cs, env->vm_vmcb + offsetof(struct vmcb, control.exit_code),
             exit_code);

    x86_stq_phys(cs, env->vm_vmcb + offsetof(struct vmcb,
                                             control.exit_info_1), exit_info_1);

    /* remove any pending exception */
    env->old_exception = -1;
    cpu_loop_exit(cs);
}

void do_vmexit(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);
    bool vmrun_failed = x86_ldq_phys(cs, env->vm_vmcb +
                                     offsetof(struct vmcb, control.exit_code))
                        == (uint64_t)SVM_EXIT_ERR;

    /* MOV SS's held #DB stays with the side the switch leaves. */
    env->db_movss = 0;
    env->hflags2 &= ~HF2_NPT_MASK;
    if (vmrun_failed) {
        env->svm_cache.valid = false;
        env->hflags &= ~HF_INHIBIT_IRQ_MASK;
        goto load_host;
    }

    if (env->hflags & HF_INHIBIT_IRQ_MASK) {
        x86_stl_phys(cs,
                 env->vm_vmcb + offsetof(struct vmcb, control.int_state),
                 SVM_INTERRUPT_SHADOW_MASK);
        env->hflags &= ~HF_INHIBIT_IRQ_MASK;
    } else {
        x86_stl_phys(cs,
                 env->vm_vmcb + offsetof(struct vmcb, control.int_state), 0);
    }

    /* Save the VM state in the vmcb */
    svm_save_seg(env, MMU_PHYS_IDX,
                 env->vm_vmcb + offsetof(struct vmcb, save.es),
                 &env->segs[R_ES]);
    svm_save_seg(env, MMU_PHYS_IDX,
                 env->vm_vmcb + offsetof(struct vmcb, save.cs),
                 &env->segs[R_CS]);
    svm_save_seg(env, MMU_PHYS_IDX,
                 env->vm_vmcb + offsetof(struct vmcb, save.ss),
                 &env->segs[R_SS]);
    svm_save_seg(env, MMU_PHYS_IDX,
                 env->vm_vmcb + offsetof(struct vmcb, save.ds),
                 &env->segs[R_DS]);

    x86_stq_phys(cs, env->vm_vmcb + offsetof(struct vmcb, save.gdtr.base),
             env->gdt.base);
    x86_stl_phys(cs, env->vm_vmcb + offsetof(struct vmcb, save.gdtr.limit),
             env->gdt.limit);

    x86_stq_phys(cs, env->vm_vmcb + offsetof(struct vmcb, save.idtr.base),
             env->idt.base);
    x86_stl_phys(cs, env->vm_vmcb + offsetof(struct vmcb, save.idtr.limit),
             env->idt.limit);

    x86_stq_phys(cs,
             env->vm_vmcb + offsetof(struct vmcb, save.efer), env->efer);
    x86_stq_phys(cs,
             env->vm_vmcb + offsetof(struct vmcb, save.cr0), env->cr[0]);
    x86_stq_phys(cs,
             env->vm_vmcb + offsetof(struct vmcb, save.cr2), env->cr[2]);
    x86_stq_phys(cs,
             env->vm_vmcb + offsetof(struct vmcb, save.cr3), env->cr[3]);
    x86_stq_phys(cs,
             env->vm_vmcb + offsetof(struct vmcb, save.cr4), env->cr[4]);
    /* A #VMEXIT during a virtual NMI's delivery saves it unblocked. */
    if (svm_vnmi_enabled(env)) {
        uint32_t event_inj = x86_ldl_phys(cs, env->vm_vmcb +
                                          offsetof(struct vmcb,
                                                   control.event_inj));

        if ((event_inj & SVM_EVTINJ_VALID) &&
            (event_inj & SVM_EVTINJ_TYPE_MASK) == SVM_EVTINJ_TYPE_NMI) {
            env->int_ctl &= ~V_NMI_BLOCKING_MASK;
        }
    }
    x86_stl_phys(cs,
             env->vm_vmcb + offsetof(struct vmcb, control.int_ctl), env->int_ctl);

    x86_stq_phys(cs, env->vm_vmcb + offsetof(struct vmcb, save.rflags),
             cpu_compute_eflags(env));
    x86_stq_phys(cs, env->vm_vmcb + offsetof(struct vmcb, save.rip),
             env->eip);
    x86_stq_phys(cs,
             env->vm_vmcb + offsetof(struct vmcb, save.rsp), env->regs[R_ESP]);
    x86_stq_phys(cs,
             env->vm_vmcb + offsetof(struct vmcb, save.rax), env->regs[R_EAX]);
    if (x86_has_shstk(env)) {
        svm_save_cet(env, env->vm_vmcb);
    }
    x86_stq_phys(cs,
             env->vm_vmcb + offsetof(struct vmcb, save.dr7), env->dr[7]);
    x86_stq_phys(cs,
             env->vm_vmcb + offsetof(struct vmcb, save.dr6), env->dr[6]);
    x86_stb_phys(cs, env->vm_vmcb + offsetof(struct vmcb, save.cpl),
             env->hflags & HF_CPL_MASK);
    if (env->svm_lbr_virt) {
        svm_store_lbr(env, env->vm_vmcb);
    }

    /* The guest state just stored is what the processor now caches. */
    if (env->svm_cache.valid) {
        SVMStateCache *c = &env->svm_cache;

        if (env->svm_lbr_virt) {
            svm_cache_lbr(env, c);
        }
        for (int i = 0; i < ARRAY_SIZE(svm_cached_segs); i++) {
            svm_cache_seg(env, &c->segs[i],
                          &env->segs[svm_cached_segs[i].reg]);
        }
        c->gdt.base = env->gdt.base;
        svm_canonicalization(env, &c->gdt.base);
        c->gdt.limit = env->gdt.limit;
        c->idt.base = env->idt.base;
        svm_canonicalization(env, &c->idt.base);
        c->idt.limit = env->idt.limit;
        c->efer = env->efer;
        c->cr0 = env->cr[0];
        c->cr2 = env->cr[2];
        c->cr3 = env->cr[3];
        c->cr4 = env->cr[4];
        c->int_ctl = env->int_ctl;
        c->dr7 = env->dr[7];
        c->dr6 = env->dr[6];
    }

    /* The guest's last CR4 is what its translations were made under. */
    env->svm_tlb_cr4 = env->cr[4];

load_host:
    /* Reload the host state from vm_hsave */
    env->hflags2 &= ~(HF2_HIF_MASK | HF2_VINTR_MASK);
    env->hflags &= ~HF_GUEST_MASK;
    env->intercept = 0;
    env->intercept_vec5 = 0;
    env->intercept_exceptions = 0;

    /*
     * Clears the V_IRQ, V_NMI and V_INTR_MASKING bits inside the processor.
     */
    cpu_reset_interrupt(cs, CPU_INTERRUPT_VIRQ | CPU_INTERRUPT_VNMI);
    env->int_ctl = 0;

    /* Clears the TSC_OFFSET inside the processor. */
    env->tsc_offset = 0;

    if (env->svm_lbr_virt) {
        svm_load_lbr(env, env->vm_hsave);
        env->svm_lbr_virt = false;
    }
    env->svm_avic = false;
    env->svm_x2avic = false;

    env->gdt.base  = x86_ldq_phys(cs, env->vm_hsave + offsetof(struct vmcb,
                                                       save.gdtr.base));
    env->gdt.limit = x86_ldl_phys(cs, env->vm_hsave + offsetof(struct vmcb,
                                                       save.gdtr.limit));

    env->idt.base  = x86_ldq_phys(cs, env->vm_hsave + offsetof(struct vmcb,
                                                       save.idtr.base));
    env->idt.limit = x86_ldl_phys(cs, env->vm_hsave + offsetof(struct vmcb,
                                                       save.idtr.limit));

    env->svm_loading_crs = true;
    cpu_x86_update_cr0(env, x86_ldq_phys(cs,
                                     env->vm_hsave + offsetof(struct vmcb,
                                                              save.cr0)) |
                       CR0_PE_MASK);
    cpu_x86_update_cr4(env, x86_ldq_phys(cs,
                                     env->vm_hsave + offsetof(struct vmcb,
                                                              save.cr4)));

    /*
     * Resets the current ASID register to zero, the host's, whose
     * translations the guest's never displaced.
     */
    cpu_x86_update_cr3(env, x86_ldq_phys(cs,
                                     env->vm_hsave + offsetof(struct vmcb,
                                                              save.cr3)));
    env->svm_loading_crs = false;
    /* we need to set the efer after the crs so the hidden flags get
       set properly */
    cpu_load_efer(env, x86_ldq_phys(cs, env->vm_hsave + offsetof(struct vmcb,
                                                         save.efer)));
    /*
     * A host with PAE paging gets the PDPTE registers from the PDPEs at its
     * CR3, where illegal state shuts the processor down (AMD64 Architecture
     * Programmer's Manual Volume 2, 24593 rev. 3.45, 15.6).
     */
    if (x86_pae_paging(env->cr[0], env->cr[4], env->efer) &&
        !x86_load_pdptes(env)) {
        qemu_log_mask(LOG_GUEST_ERROR, "#VMEXIT: illegal host PDPEs\n");
        qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
    }

    /* Completion of the VMRUN instruction clears the host EFLAGS.RF bit.  */
    env->eflags = 0;
    cpu_load_eflags(env, x86_ldq_phys(cs,
                                  env->vm_hsave + offsetof(struct vmcb,
                                                           save.rflags)),
                    ~(CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C | DF_MASK |
                      RF_MASK | VM_MASK));

    svm_load_seg_cache(env, MMU_PHYS_IDX,
                       env->vm_hsave + offsetof(struct vmcb, save.es), R_ES);
    svm_load_seg_cache(env, MMU_PHYS_IDX,
                       env->vm_hsave + offsetof(struct vmcb, save.cs), R_CS);
    svm_load_seg_cache(env, MMU_PHYS_IDX,
                       env->vm_hsave + offsetof(struct vmcb, save.ss), R_SS);
    svm_load_seg_cache(env, MMU_PHYS_IDX,
                       env->vm_hsave + offsetof(struct vmcb, save.ds), R_DS);

    env->eip = x86_ldq_phys(cs,
                        env->vm_hsave + offsetof(struct vmcb, save.rip));
    env->regs[R_ESP] = x86_ldq_phys(cs, env->vm_hsave +
                                offsetof(struct vmcb, save.rsp));
    env->regs[R_EAX] = x86_ldq_phys(cs, env->vm_hsave +
                                offsetof(struct vmcb, save.rax));
    if (x86_has_shstk(env)) {
        svm_load_cet(env, env->vm_hsave);
    }

    env->dr[6] = x86_ldq_phys(cs,
                          env->vm_hsave + offsetof(struct vmcb, save.dr6));

    /* Disables all breakpoints in the host DR7 register. */
    cpu_x86_update_dr7(env,
             x86_ldq_phys(cs,
                          env->vm_hsave + offsetof(struct vmcb, save.dr7)) & ~0xff);

    /* other setups */
    x86_stl_phys(cs,
             env->vm_vmcb + offsetof(struct vmcb, control.exit_int_info),
             x86_ldl_phys(cs, env->vm_vmcb + offsetof(struct vmcb,
                                              control.event_inj)));
    x86_stl_phys(cs,
             env->vm_vmcb + offsetof(struct vmcb, control.exit_int_info_err),
             x86_ldl_phys(cs, env->vm_vmcb + offsetof(struct vmcb,
                                              control.event_inj_err)));
    x86_stl_phys(cs,
             env->vm_vmcb + offsetof(struct vmcb, control.event_inj), 0);

    env->hflags2 &= ~HF2_GIF_MASK;
    env->hflags2 &= ~HF2_VGIF_MASK;


    /* FIXME: Checks the reloaded host state for consistency. */

    /*
     * EFLAGS.TF causes a #DB trap after the VMRUN completes on the host
     * side (i.e., after the #VMEXIT from the guest). Since we're running
     * in the main loop, call do_interrupt_all directly.
     */
    if ((env->eflags & TF_MASK) != 0) {
        env->dr[6] |= DR6_BS;
        do_interrupt_all(X86_CPU(cs), EXCP01_DB, 0, 0, env->eip, 0);
    }
}
