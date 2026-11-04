/*
 *  x86 exception helpers - system code
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
#include "cpu.h"
#include "accel/tcg/cpu-ldst.h"
#include "accel/tcg/cpu-loop.h"
#include "accel/tcg/probe.h"
#include "exec/cputlb.h"
#include "exec/page-protection.h"
#include "exec/target_page.h"
#include "exec/tlb-flags.h"
#include "tcg/helper-tcg.h"

typedef struct TranslateParams {
    target_ulong addr;
    target_ulong cr3;
    int pg_mode;
    int mmu_idx;
    int ptw_idx;
    MMUAccessType access_type;
    /* The PDPTE registers PAE paging takes instead of memory, or NULL. */
    const uint64_t *pdptes;
} TranslateParams;

typedef struct TranslateResult {
    hwaddr paddr;
    int prot;
    int page_size;
    /* paddr is an offset in the AVIC address space's vAPIC page. */
    bool avic;
} TranslateResult;

typedef enum TranslateFaultStage2 {
    S2_NONE,
    S2_GPA,
    S2_GPT,
} TranslateFaultStage2;

typedef struct TranslateFault {
    int exception_index;
    int error_code;
    target_ulong cr2;
    TranslateFaultStage2 stage2;
} TranslateFault;

typedef struct PTETranslate {
    CPUX86State *env;
    TranslateFault *err;
    int ptw_idx;
    void *haddr;
    hwaddr gaddr;
    /* The entry was probed for loads, so flag updates probe for a store. */
    bool load_only;
    /* A flag update met an EPT violation, which ends the walk. */
    bool fault;
} PTETranslate;

static bool ptw_translate(PTETranslate *inout, hwaddr addr)
{
    int flags;

    /*
     * Walks may set accessed and dirty flags: stores, but for EPT without
     * A/D flags, which takes paging-structure accesses as reads (Intel SDM
     * 325462-093 Vol. 3C, 31.3.5).
     */
    inout->gaddr = addr;
    inout->load_only = x86_vmx_ept_active(inout->env) &&
                       !x86_vmx_ept_ad(inout->env);
    flags = probe_access_full_mmu(inout->env, addr, 0,
                                  inout->load_only ? MMU_DATA_LOAD
                                                   : MMU_DATA_STORE,
                                  inout->ptw_idx, &inout->haddr, NULL);

    if (unlikely(flags & TLB_INVALID_MASK)) {
        TranslateFault *err = inout->err;

        assert(inout->ptw_idx == MMU_NESTED_IDX ||
               inout->ptw_idx == MMU_NESTED_SUP_IDX);
        *err = (TranslateFault){
            .error_code = inout->env->error_code,
            .cr2 = addr,
            .stage2 = S2_GPT,
        };
        return false;
    }
    return true;
}

static inline uint32_t ptw_ldl(const PTETranslate *in, uint64_t ra)
{
    if (likely(in->haddr)) {
        return ldl_p(in->haddr);
    }
    return cpu_ldl_le_mmuidx_ra(in->env, in->gaddr, in->ptw_idx, ra);
}

static inline uint64_t ptw_ldq(const PTETranslate *in, uint64_t ra)
{
    if (likely(in->haddr)) {
        return ldq_p(in->haddr);
    }
    return cpu_ldq_le_mmuidx_ra(in->env, in->gaddr, in->ptw_idx, ra);
}

/*
 * Note that we can use a 32-bit cmpxchg for all page table entries,
 * even 64-bit ones, because PG_PRESENT_MASK, PG_ACCESSED_MASK and
 * PG_DIRTY_MASK are all in the low 32 bits.
 */
static bool ptw_setl_slow(PTETranslate *in, uint32_t old, uint32_t new)
{
    uint32_t cmp;

    CPUState *cpu = env_cpu(in->env);
    /* We are in cpu_exec, and start_exclusive can't be called directly.*/
    g_assert(cpu->running);
    cpu_exec_end(cpu);
    /* Does x86 really perform a rmw cycle on mmio for ptw? */
    start_exclusive();
    cmp = cpu_ldl_le_mmuidx_ra(in->env, in->gaddr, in->ptw_idx, 0);
    if (cmp == old) {
        cpu_stl_le_mmuidx_ra(in->env, in->gaddr, new, in->ptw_idx, 0);
    }
    end_exclusive();
    cpu_exec_start(cpu);
    return cmp == old;
}

/*
 * The flag update of an entry probed for loads needs EPT write permission
 * first; a violation ends the walk.
 */
static bool ptw_store(PTETranslate *in)
{
    int flags = probe_access_full_mmu(in->env, in->gaddr, 0, MMU_DATA_STORE,
                                      in->ptw_idx, &in->haddr, NULL);

    if (unlikely(flags & TLB_INVALID_MASK)) {
        *in->err = (TranslateFault){
            .error_code = in->env->error_code,
            .cr2 = in->gaddr,
            .stage2 = S2_GPT,
        };
        in->fault = true;
        return false;
    }
    in->load_only = false;
    return true;
}

static inline bool ptw_setl(PTETranslate *in, uint32_t old, uint32_t set)
{
    if (set & ~old) {
        uint32_t new = old | set;

        if (unlikely(in->load_only) && !ptw_store(in)) {
            return false;
        }
        if (likely(in->haddr)) {
            old = cpu_to_le32(old);
            new = cpu_to_le32(new);
            return qatomic_cmpxchg((uint32_t *)in->haddr, old, new) == old;
        }
        return ptw_setl_slow(in, old, new);
    }
    return true;
}

static bool mmu_translate(CPUX86State *env, const TranslateParams *in,
                          TranslateResult *out, TranslateFault *err,
                          uint64_t ra)
{
    const target_ulong addr = in->addr;
    const int pg_mode = in->pg_mode;
    const bool is_user = is_mmu_index_user(in->mmu_idx);
    const bool ss = is_mmu_index_ss(in->mmu_idx);
    const MMUAccessType access_type = in->access_type;
    uint64_t ptep, pte, rsvd_mask;
    /* The access rights of the entries above the one that maps the page. */
    uint64_t ptep_upper = -1;
    PTETranslate pte_trans = {
        .env = env,
        .err = err,
        .ptw_idx = in->ptw_idx,
    };
    hwaddr pte_addr, paddr;
    uint32_t pkr;
    int page_size;
    int error_code;
    int prot;
    /*
     * PML5Es and PML4Es have no PS bit; AMD reserves their bit 8 too
     * (AMD64 Architecture Programmer's Manual Volume 2, 24593 rev. 3.45,
     * Figures 5-19 and 5-20).
     */
    const uint64_t top_rsvd = PG_PSE_MASK |
        (IS_AMD_CPU(env) ? PG_GLOBAL_MASK : 0);

 restart_all:
    ptep_upper = -1;
    rsvd_mask = ~MAKE_64BIT_MASK(0, env_archcpu(env)->phys_bits);
    rsvd_mask &= PG_ADDRESS_MASK;
    if (!(pg_mode & PG_MODE_NXE)) {
        rsvd_mask |= PG_NX_MASK;
    }

    if (pg_mode & PG_MODE_PAE) {
#ifdef TARGET_X86_64
        if (pg_mode & PG_MODE_LMA) {
            if (pg_mode & PG_MODE_LA57) {
                /*
                 * Page table level 5
                 */
                pte_addr = (in->cr3 & PG_ADDRESS_MASK) +
                           (((addr >> 48) & 0x1ff) << 3);
                if (!ptw_translate(&pte_trans, pte_addr)) {
                    return false;
                }
            restart_5:
                pte = ptw_ldq(&pte_trans, ra);
                if (!(pte & PG_PRESENT_MASK)) {
                    goto do_fault;
                }
                if (pte & (rsvd_mask | top_rsvd)) {
                    goto do_fault_rsvd;
                }
                if (!ptw_setl(&pte_trans, pte, PG_ACCESSED_MASK)) {
                    if (pte_trans.fault) {
                        return false;
                    }
                    goto restart_5;
                }
                ptep = pte ^ PG_NX_MASK;
            } else {
                pte = in->cr3;
                ptep = PG_NX_MASK | PG_USER_MASK | PG_RW_MASK;
            }

            /*
             * Page table level 4
             */
            pte_addr = (pte & PG_ADDRESS_MASK) + (((addr >> 39) & 0x1ff) << 3);
            if (!ptw_translate(&pte_trans, pte_addr)) {
                return false;
            }
        restart_4:
            pte = ptw_ldq(&pte_trans, ra);
            if (!(pte & PG_PRESENT_MASK)) {
                goto do_fault;
            }
            if (pte & (rsvd_mask | top_rsvd)) {
                goto do_fault_rsvd;
            }
            if (!ptw_setl(&pte_trans, pte, PG_ACCESSED_MASK)) {
                if (pte_trans.fault) {
                    return false;
                }
                goto restart_4;
            }
            ptep &= pte ^ PG_NX_MASK;

            /*
             * Page table level 3
             */
            pte_addr = (pte & PG_ADDRESS_MASK) + (((addr >> 30) & 0x1ff) << 3);
            if (!ptw_translate(&pte_trans, pte_addr)) {
                return false;
            }
        restart_3_lma:
            pte = ptw_ldq(&pte_trans, ra);
            if (!(pte & PG_PRESENT_MASK)) {
                goto do_fault;
            }
            if (pte & rsvd_mask) {
                goto do_fault_rsvd;
            }
            if (!ptw_setl(&pte_trans, pte, PG_ACCESSED_MASK)) {
                if (pte_trans.fault) {
                    return false;
                }
                goto restart_3_lma;
            }
            ptep_upper = ptep;
            ptep &= pte ^ PG_NX_MASK;
            if (pte & PG_PSE_MASK) {
                /* 1 GB page */
                page_size = 1024 * 1024 * 1024;
                goto do_check_protect;
            }
        } else
#endif
        {
            /*
             * Page table level 3
             */
            rsvd_mask |= PG_HI_USER_MASK;
            if (in->pdptes) {
                pte = in->pdptes[(addr >> 30) & 3];
            } else {
                pte_addr = (in->cr3 & 0xffffffe0ULL) + ((addr >> 27) & 0x18);
                if (!ptw_translate(&pte_trans, pte_addr)) {
                    return false;
                }
                pte = ptw_ldq(&pte_trans, ra);
            }
            if (!(pte & PG_PRESENT_MASK)) {
                goto do_fault;
            }
            if (pte & (rsvd_mask | PG_NX_MASK)) {
                goto do_fault_rsvd;
            }
            /* PAE paging's PDPTEs have no accessed flag: bit 5 is reserved. */
            ptep = PG_NX_MASK | PG_USER_MASK | PG_RW_MASK;
        }

        /*
         * Page table level 2
         */
        pte_addr = (pte & PG_ADDRESS_MASK) + (((addr >> 21) & 0x1ff) << 3);
        if (!ptw_translate(&pte_trans, pte_addr)) {
            return false;
        }
    restart_2_pae:
        pte = ptw_ldq(&pte_trans, ra);
        if (!(pte & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        if (pte & rsvd_mask) {
            goto do_fault_rsvd;
        }
        ptep_upper = ptep;
        if (pte & PG_PSE_MASK) {
            /* 2 MB page */
            page_size = 2048 * 1024;
            ptep &= pte ^ PG_NX_MASK;
            goto do_check_protect;
        }
        if (!ptw_setl(&pte_trans, pte, PG_ACCESSED_MASK)) {
            if (pte_trans.fault) {
                return false;
            }
            goto restart_2_pae;
        }
        ptep &= pte ^ PG_NX_MASK;

        /*
         * Page table level 1
         */
        pte_addr = (pte & PG_ADDRESS_MASK) + (((addr >> 12) & 0x1ff) << 3);
        if (!ptw_translate(&pte_trans, pte_addr)) {
            return false;
        }
        pte = ptw_ldq(&pte_trans, ra);
        if (!(pte & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        if (pte & rsvd_mask) {
            goto do_fault_rsvd;
        }
        /* combine pde and pte nx, user and rw protections */
        ptep_upper = ptep;
        ptep &= pte ^ PG_NX_MASK;
        page_size = 4096;
    } else if (pg_mode & PG_MODE_PG) {
        /*
         * Page table level 2
         */
        pte_addr = (in->cr3 & 0xfffff000ULL) + ((addr >> 20) & 0xffc);
        if (!ptw_translate(&pte_trans, pte_addr)) {
            return false;
        }
    restart_2_nopae:
        pte = ptw_ldl(&pte_trans, ra);
        if (!(pte & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        ptep = pte | PG_NX_MASK;

        /* if PSE bit is set, then we use a 4MB page */
        if ((pte & PG_PSE_MASK) && (pg_mode & PG_MODE_PSE)) {
            page_size = 4096 * 1024;
            /*
             * Bits 20-13 provide bits 39-32 of the address, bit 21 is reserved.
             * Leave bits 20-13 in place for setting accessed/dirty bits below.
             */
            pte = (uint32_t)pte | ((pte & 0x1fe000LL) << (32 - 13));
            rsvd_mask = 0x200000;
            goto do_check_protect_pse36;
        }
        if (!ptw_setl(&pte_trans, pte, PG_ACCESSED_MASK)) {
            if (pte_trans.fault) {
                return false;
            }
            goto restart_2_nopae;
        }

        /*
         * Page table level 1
         */
        pte_addr = (pte & ~0xfffu) + ((addr >> 10) & 0xffc);
        if (!ptw_translate(&pte_trans, pte_addr)) {
            return false;
        }
        pte = ptw_ldl(&pte_trans, ra);
        if (!(pte & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        /* combine pde and pte user and rw protections */
        ptep_upper = ptep;
        ptep &= pte | PG_NX_MASK;
        page_size = 4096;
        rsvd_mask = 0;
    } else {
        /*
         * No paging (real mode), let's tentatively resolve the address as 1:1
         * here, but conditionally still perform an NPT walk on it later.
         */
        page_size = 0x40000000;
        paddr = in->addr;
        prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        /* Without paging, a user-mode, read/write, executable page. */
        ptep = PG_USER_MASK | PG_RW_MASK;
        goto stage2;
    }

do_check_protect:
    rsvd_mask |= (page_size - 1) & PG_ADDRESS_MASK & ~PG_PSE_PAT_MASK;
do_check_protect_pse36:
    if (pte & rsvd_mask) {
        goto do_fault_rsvd;
    }
    ptep ^= PG_NX_MASK;

    /* can the page can be put in the TLB?  prot will tell us */
    if (is_user && !(ptep & PG_USER_MASK)) {
        goto do_fault_protect;
    }

    prot = 0;
    if (ss) {
        /*
         * Shadow-stack accesses reach only shadow-stack pages of their own
         * mode: read-only and dirty in the entry that maps the page,
         * writable in every other one (Intel SDM 325462-093 Vol. 3A, 5.6.1).
         */
        if ((pte & (PG_RW_MASK | PG_DIRTY_MASK)) != PG_DIRTY_MASK ||
            !(ptep_upper & PG_RW_MASK) ||
            (!is_user && (ptep & PG_USER_MASK))) {
            goto do_fault_protect;
        }
        prot = PAGE_READ | PAGE_WRITE;
    } else if (!is_mmu_index_smap(in->mmu_idx) || !(ptep & PG_USER_MASK)) {
        prot |= PAGE_READ;
        if ((ptep & PG_RW_MASK) || !(is_user || (pg_mode & PG_MODE_WP))) {
            prot |= PAGE_WRITE;
        }
    }
    if (!ss && !(ptep & PG_NX_MASK) &&
        (is_user ||
         !((pg_mode & PG_MODE_SMEP) && (ptep & PG_USER_MASK)))) {
        prot |= PAGE_EXEC;
    }

    if (ptep & PG_USER_MASK) {
        pkr = pg_mode & PG_MODE_PKE ? env->pkru : 0;
    } else {
        pkr = pg_mode & PG_MODE_PKS ? env->pkrs : 0;
    }
    if (pkr) {
        uint32_t pk = (pte & PG_PKRU_MASK) >> PG_PKRU_BIT;
        uint32_t pkr_ad = (pkr >> pk * 2) & 1;
        uint32_t pkr_wd = (pkr >> pk * 2) & 2;
        uint32_t pkr_prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;

        if (pkr_ad) {
            pkr_prot &= ~(PAGE_READ | PAGE_WRITE);
        } else if (pkr_wd && (is_user || (pg_mode & PG_MODE_WP))) {
            pkr_prot &= ~PAGE_WRITE;
        }
        if ((pkr_prot & (1 << access_type)) == 0) {
            goto do_fault_pk_protect;
        }
        prot &= pkr_prot;
    }

    if ((prot & (1 << access_type)) == 0) {
        goto do_fault_protect;
    }

    /* yes, it can! */
    {
        uint32_t set = PG_ACCESSED_MASK;
        if (access_type == MMU_DATA_STORE) {
            set |= PG_DIRTY_MASK;
        } else if (!(pte & PG_DIRTY_MASK)) {
            /*
             * Only set write access if already dirty...
             * otherwise wait for dirty access.
             */
            prot &= ~PAGE_WRITE;
        }
        if (!ptw_setl(&pte_trans, pte, set)) {
            if (pte_trans.fault) {
                return false;
            }
            /*
             * We can arrive here from any of 3 levels and 2 formats.
             * The only safe thing is to restart the entire lookup.
             */
            goto restart_all;
        }
    }

    /* merge offset within page */
    paddr = (pte & PG_ADDRESS_MASK & ~(page_size - 1)) | (addr & (page_size - 1));
 stage2:

    /*
     * Note that NPT is walked (for both paging structures and final guest
     * addresses) using the address with the A20 bit set.
     */
    if (in->ptw_idx != MMU_PHYS_IDX) {
        CPUTLBEntryFull *full;
        int flags, nested_page_size;
        int idx = in->ptw_idx;

        /*
         * A linear address is user-mode where every paging-structure entry
         * has U/S set, or without paging (Intel SDM 325462-093 Vol. 3C,
         * 31.3.3.2).
         */
        if (x86_vmx_ept_mbec(env) && !(ptep & PG_USER_MASK)) {
            idx = MMU_NESTED_SUP_IDX;
        }
        flags = probe_access_full_mmu(env, paddr, 0, access_type,
                                      idx, &pte_trans.haddr, &full);
        if (unlikely(flags & TLB_INVALID_MASK)) {
            x86_vmx_ept_guest_page(env, ptep);
            *err = (TranslateFault){
                .error_code = env->error_code,
                .cr2 = paddr,
                .stage2 = S2_GPA,
            };
            return false;
        }

        /* Merge stage1 & stage2 protection bits. */
        prot &= full->prot;

        /* Re-verify resulting protection. */
        if ((prot & (1 << access_type)) == 0) {
            goto do_fault_protect;
        }

        /*
         * xAVIC sends the guest's data accesses to its vAPIC page, which
         * the nested page table must map, to the backing page instead
         * (AMD64 Architecture Programmer's Manual Volume 2, 24593 rev.
         * 3.45, 15.29.3): to the AVIC address space's page.
         */
        if (unlikely(env->svm_avic) && !env->svm_x2avic &&
            access_type != MMU_INST_FETCH &&
            (paddr & TARGET_PAGE_MASK) == env->svm_avic_bar) {
            out->paddr = paddr & ~TARGET_PAGE_MASK;
            out->prot = prot & ~PAGE_EXEC;
            out->page_size = TARGET_PAGE_SIZE;
            out->avic = true;
            return true;
        }

        /* Merge stage1 & stage2 addresses to final physical address. */
        nested_page_size = 1 << full->lg_page_size;
        paddr = (full->phys_addr & ~(nested_page_size - 1))
              | (paddr & (nested_page_size - 1));

        /*
         * Use the larger of stage1 & stage2 page sizes, so that
         * invalidation works.
         */
        if (nested_page_size > page_size) {
            page_size = nested_page_size;
        }
    }

    out->paddr = paddr & x86_get_a20_mask(env);
    out->prot = prot;
    out->page_size = page_size;
    return true;

 do_fault_rsvd:
    /* Only present entries can have reserved bits set. */
    error_code = PG_ERROR_RSVD_MASK | PG_ERROR_P_MASK;
    goto do_fault_cont;
 do_fault_protect:
    error_code = PG_ERROR_P_MASK;
    goto do_fault_cont;
 do_fault_pk_protect:
    assert(access_type != MMU_INST_FETCH);
    error_code = PG_ERROR_PK_MASK | PG_ERROR_P_MASK;
    goto do_fault_cont;
 do_fault:
    error_code = 0;
 do_fault_cont:
    if (is_user) {
        error_code |= PG_ERROR_U_MASK;
    }
    if (ss) {
        error_code |= PG_ERROR_SS_MASK;
    }
    switch (access_type) {
    case MMU_DATA_LOAD:
        break;
    case MMU_DATA_STORE:
        error_code |= PG_ERROR_W_MASK;
        break;
    case MMU_INST_FETCH:
        if (pg_mode & (PG_MODE_NXE | PG_MODE_SMEP | PG_MODE_NESTED_SMEP)) {
            error_code |= PG_ERROR_I_D_MASK;
        }
        break;
    }
    *err = (TranslateFault){
        .exception_index = EXCP0E_PAGE,
        .error_code = error_code,
        .cr2 = addr,
    };
    return false;
}

static G_NORETURN void raise_stage2(CPUX86State *env, TranslateFault *err,
                                    vaddr linear, uintptr_t retaddr)
{
    uint64_t exit_info_1 = err->error_code;

    if (env->vmx.nonroot) {
        x86_vmx_ept_exit(env, err->cr2, linear, err->stage2 == S2_GPA,
                         retaddr);
    }

    switch (err->stage2) {
    case S2_GPT:
        exit_info_1 |= SVM_NPTEXIT_GPT;
        break;
    case S2_GPA:
        exit_info_1 |= SVM_NPTEXIT_GPA;
        break;
    default:
        g_assert_not_reached();
    }

    x86_stq_phys(env_cpu(env),
                 env->vm_vmcb + offsetof(struct vmcb, control.exit_info_2),
                 err->cr2);
    cpu_vmexit(env, SVM_EXIT_NPF, exit_info_1, retaddr);
}

/*
 * Linear-address-space separation, in IA-32e mode with CR4.LASS (Intel SDM
 * 325462-093 Vol. 3A, 4.3.2): user accesses fault in the upper half, which
 * bit 63 picks, supervisor fetches in the lower half, and supervisor data
 * accesses there where SMAP applies to them, as it does to supervisor
 * shadow-stack accesses; addresses of 32 bits are in the lower half. The
 * fault is #GP(0), also for stack accesses, where it should be #SS(0).
 */
static bool lass_violation(CPUX86State *env, vaddr addr,
                           MMUAccessType access_type, int mmu_idx)
{
    bool upper = addr >> 63;

    if (is_mmu_index_user(mmu_idx)) {
        return upper;
    }
    if (upper) {
        return false;
    }
    if (access_type == MMU_INST_FETCH) {
        return true;
    }
    return is_mmu_index_ss(mmu_idx) ? !!(env->cr[4] & CR4_SMAP_MASK)
                                    : is_mmu_index_smap(mmu_idx);
}

static bool get_physical_address(CPUX86State *env, vaddr addr,
                                 MMUAccessType access_type, int mmu_idx,
                                 TranslateResult *out, TranslateFault *err,
                                 uint64_t ra)
{
    TranslateParams in;
    bool use_stage2 = env->hflags2 & HF2_NPT_MASK;

    out->avic = false;
    in.addr = addr;
    in.access_type = access_type;

    switch (mmu_idx) {
    case MMU_PHYS_IDX:
        break;

    case MMU_NESTED_IDX:
    case MMU_NESTED_SUP_IDX:
        if (x86_vmx_ept_active(env)) {
            hwaddr hpa;

            if (!x86_vmx_ept_translate(env, addr, access_type,
                                       mmu_idx == MMU_NESTED_SUP_IDX, &hpa,
                                       &out->prot, &out->page_size)) {
                *err = (TranslateFault){ .stage2 = S2_GPA, .cr2 = addr };
                return false;
            }
            out->paddr = hpa;
            return true;
        }
        if (likely(use_stage2)) {
            bool lma = env->nested_pg_mode & PG_MODE_LMA;

            in.cr3 = env->nested_cr3;
            in.pdptes = NULL;
            in.pg_mode = env->nested_pg_mode;
            in.mmu_idx = lma ? MMU_USER64_IDX : MMU_USER32_IDX;
            /*
             * Nested accesses are user ones, but with GMET the U/S bit only
             * keeps code of guest CPL 0 to 2 from executing (AMD64
             * Architecture Programmer's Manual Volume 2, 24593 rev. 3.45,
             * 15.25.13): they are supervisor ones, read-only pages kept
             * from writes, with SMEP for those of guest supervisor accesses.
             */
            if (env->nested_pg_mode & PG_MODE_GMET) {
                in.mmu_idx = lma ? MMU_KNOSMAP64_IDX : MMU_KNOSMAP32_IDX;
                in.pg_mode |= PG_MODE_WP;
                if (mmu_idx == MMU_NESTED_SUP_IDX) {
                    in.pg_mode |= PG_MODE_SMEP;
                }
            }
            in.ptw_idx = MMU_PHYS_IDX;

            if (!mmu_translate(env, &in, out, err, ra)) {
                err->stage2 = S2_GPA;
                return false;
            }
            return true;
        }
        break;

    default:
        /* Shadow-stack addresses are 32-bit ones outside IA-32e mode. */
        if (is_mmu_index_ss(mmu_idx) ? !(env->hflags & HF_LMA_MASK)
                                     : is_mmu_index_32(mmu_idx)) {
            addr = (uint32_t)addr;
        }

        if (likely(env->cr[0] & CR0_PG_MASK || use_stage2)) {
            in.cr3 = env->cr[3];
            in.pdptes = use_stage2 && env->vmx.pdpte_loaded ?
                        env->vmx.pdpte : NULL;
            in.mmu_idx = mmu_idx;
            in.ptw_idx = MMU_PHYS_IDX;
            if (use_stage2) {
                in.ptw_idx = (env->nested_pg_mode & PG_MODE_GMET) &&
                             !is_mmu_index_user(mmu_idx) ?
                             MMU_NESTED_SUP_IDX : MMU_NESTED_IDX;
            }
            in.pg_mode = get_pg_mode(env);

            if (in.pg_mode & PG_MODE_LMA) {
                /* test virtual address sign extension */
                int shift = in.pg_mode & PG_MODE_LA57 ? 56 : 47;
                int64_t sext = (int64_t)addr >> shift;
                if (sext != 0 && sext != -1) {
                    *err = (TranslateFault){
                        .exception_index = EXCP0D_GPF,
                        /* non-canonical #GP doesn't change CR2 */
                        .cr2 = env->cr[2],
                    };
                    return false;
                }
                if ((env->cr[4] & CR4_LASS_MASK) &&
                    lass_violation(env, addr, access_type, mmu_idx)) {
                    *err = (TranslateFault){
                        .exception_index = EXCP0D_GPF,
                        .cr2 = env->cr[2],
                    };
                    return false;
                }
            }
            return mmu_translate(env, &in, out, err, ra);
        }
        break;
    }

    /* No translation needed. */
    out->paddr = addr & x86_get_a20_mask(env);
    out->prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
    out->page_size = TARGET_PAGE_SIZE;
    return true;
}

/*
 * Decode assists: up to 15 bytes at the guest's CS:RIP for a nested or
 * intercepted page fault of a data access, fewer where fetching them faults,
 * none for a fetch's (AMD64 Architecture Programmer's Manual Volume 2, 24593
 * rev. 3.45, 15.8.4).
 */
static void svm_fetch_insn_bytes(CPUX86State *env, MMUAccessType access_type,
                                 uintptr_t retaddr)
{
    CPUState *cs = env_cpu(env);
    target_ulong page = -1;
    hwaddr frame = 0;
    int mmu_idx;
    int n;

    if (!(env->features[FEAT_SVM] & CPUID_SVM_DECODEASSIST)) {
        return;
    }
    env->svm_insn_fetched = 0;
    env->svm_insn_bytes_valid = true;
    if (access_type == MMU_INST_FETCH) {
        return;
    }

    cpu_restore_state(cs, retaddr);
    mmu_idx = cpu_mmu_index(cs, true);
    for (n = 0; n < sizeof(env->svm_insn_bytes); n++) {
        target_ulong eip = env->eip + n;
        target_ulong addr;

        if (env->hflags & HF_CS64_MASK) {
            addr = env->segs[R_CS].base + eip;
        } else {
            eip = env->hflags & HF_CS32_MASK ? (uint32_t)eip : (uint16_t)eip;
            if (eip > env->segs[R_CS].limit) {
                break;
            }
            addr = (uint32_t)(env->segs[R_CS].base + eip);
        }
        if ((addr & TARGET_PAGE_MASK) != page) {
            TranslateResult out;
            TranslateFault err;

            if (!get_physical_address(env, addr, MMU_INST_FETCH, mmu_idx,
                                      &out, &err, 0)) {
                break;
            }
            page = addr & TARGET_PAGE_MASK;
            frame = out.paddr & TARGET_PAGE_MASK;
        }
        env->svm_insn_bytes[n] = x86_ldub_phys(cs, frame |
                                               (addr & ~TARGET_PAGE_MASK));
    }
    env->svm_insn_fetched = n;
}

bool x86_cpu_tlb_fill(CPUState *cs, vaddr addr, int size,
                      MMUAccessType access_type, int mmu_idx,
                      bool probe, uintptr_t retaddr)
{
    CPUX86State *env = cpu_env(cs);
    TranslateResult out;
    TranslateFault err;

    if (get_physical_address(env, addr, access_type, mmu_idx, &out, &err,
                             retaddr)) {
        MemTxAttrs attrs = cpu_get_mem_attrs(env);

        /*
         * Linear accesses to VMX's APIC-access page (Intel SDM 325462-093
         * Vol. 3C, 32.4): fetches exit, data accesses go to the AVIC
         * address space's page, where VMX virtualizes them or exits.
         */
        if (unlikely(env->vmx.nonroot) &&
            ((1 << mmu_idx) & MMU_GUEST_IDX_MAP) &&
            (out.paddr & TARGET_PAGE_MASK) == env->vmx.apic_access) {
            if (access_type == MMU_INST_FETCH) {
                if (probe) {
                    return false;
                }
                x86_vmx_apic_fetch_exit(env, addr, retaddr);
            }
            out.paddr &= ~TARGET_PAGE_MASK;
            out.prot &= ~PAGE_EXEC;
            out.page_size = TARGET_PAGE_SIZE;
            out.avic = true;
        }
        attrs.avic = out.avic;
        /*
         * Even if 4MB pages, we map only one 4KB page in the cache to
         * avoid filling it too fast.
         */
        assert(out.prot & (1 << access_type));
        tlb_set_page_with_attrs(cs, addr & TARGET_PAGE_MASK,
                                out.paddr & TARGET_PAGE_MASK, attrs,
                                out.prot, mmu_idx, out.page_size);
        return true;
    }

    if (probe) {
        /* This will be used if recursing for stage2 translation. */
        env->error_code = err.error_code;
        return false;
    }

    if (err.stage2 != S2_NONE) {
        if (!env->vmx.nonroot) {
            svm_fetch_insn_bytes(env, access_type, retaddr);
        }
        raise_stage2(env, &err, addr, retaddr);
    }

    if (env->intercept_exceptions & (1 << err.exception_index)) {
        /* cr2 is not modified in case of exceptions */
        x86_stq_phys(cs, env->vm_vmcb +
                     offsetof(struct vmcb, control.exit_info_2),
                     err.cr2);
        if (err.exception_index == EXCP0E_PAGE) {
            svm_fetch_insn_bytes(env, access_type, retaddr);
        }
    } else if (env->vmx.nonroot &&
               x86_vmx_exception_exits(env, err.exception_index,
                                       err.error_code)) {
        /* An exiting #PF gives its address in the exit qualification. */
        env->vmx.exception_qual = err.cr2;
    } else {
        env->cr[2] = err.cr2;
    }
    raise_exception_err_ra(env, err.exception_index, err.error_code, retaddr);
}

G_NORETURN void x86_cpu_do_unaligned_access(CPUState *cs, vaddr vaddr,
                                            MMUAccessType access_type,
                                            int mmu_idx, uintptr_t retaddr)
{
    X86CPU *cpu = X86_CPU(cs);
    handle_unaligned_access(&cpu->env, vaddr, access_type, retaddr);
}
