/*
 * x86 bus locks for TCG (system emulator)
 *
 * A locked read-modify-write access asserts a bus lock where it splits
 * cache lines or its memory type is not WB (Intel SDM 325462-093 Vol. 3A,
 * 11.1.2; AMD64 Architecture Programmer's Manual Volume 2, 24593 rev. 3.46,
 * 7.3.3). OS bus-lock detection then raises a trap-like #DB after an
 * instruction at CPL > 0 that asserted one (Intel SDM 325462-093 Vol. 3B,
 * 20.3.1.6; AMD64 Architecture Programmer's Manual Volume 2, 24593 rev.
 * 3.46, 13.1.3.6); split-lock disable and UC-lock disable make such
 * accesses fault instead (Intel SDM 325462-093 Vol. 3A, 11.1.2.3), also
 * the implicit locked updates of paging-structure entries and descriptors
 * (Intel SDM 325462-093 Vol. 3A, 11.1.2.1); VMX's "VMM bus-lock detection"
 * exits after any (Intel SDM 325462-093 Vol. 3C, 28.2).
 *
 * The translator checks locked instructions only once some processor
 * watches for bus locks: x86_bus_lock_watch() then flushes all
 * translations, and the checks stay.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/tb-flush.h"
#include "exec/target_page.h"
#include "exec/translation-block.h"
#include "accel/tcg/cpu-loop.h"
#include "accel/tcg/probe.h"
#include "tcg/helper-tcg.h"
#include "../seg_helper.h"

bool x86_bus_lock_checks;

void x86_bus_lock_watch(CPUX86State *env)
{
    if (!qatomic_read(&x86_bus_lock_checks)) {
        qatomic_set(&x86_bus_lock_checks, true);
        queue_tb_flush(env_cpu(env));
    }
}

/* OS bus-lock detection, which watches CPL > 0. */
static bool os_bld(CPUX86State *env)
{
    return (env->debugctl & DEBUGCTL_BLD) && (env->hflags & HF_CPL_MASK);
}

/* VMX's "VMM bus-lock detection" in non-root operation. */
static bool vmx_bus_lock(CPUX86State *env)
{
    return env->vmx.nonroot && env->vmx.bus_lock;
}

/* UC-lock disable, which CR0.CD turns off. */
static bool uc_lock_disabled(CPUX86State *env)
{
    return (env->memory_ctrl & MEMORY_CTRL_UC_LOCK_DISABLE) &&
           !(env->cr[0] & CR0_CD_MASK);
}

/* A UC lock under UC-lock disable, as CPUID.07H.02H:EDX[6] enumerates it. */
static G_NORETURN void uc_lock_fault(CPUX86State *env, uintptr_t ra)
{
    raise_exception_err_ra(env, EXCP11_ALGN, 4, ra);
}

/*
 * Whether memory at PA is WB, where its page-level type is WB as WB says,
 * which the MTRRs join where MTRR says so: CR0.CD makes accesses
 * uncacheable, under nested paging the host's as well as the guest's
 * (Intel SDM 325462-093 Vol. 3A, 14.5.2 and Vol. 3C, 31.3.7.2; AMD64
 * Architecture Programmer's Manual Volume 2, 24593 rev. 3.46, 7.4 and
 * 15.25.9).
 */
bool x86_bus_lock_wb(CPUX86State *env, bool wb, bool mtrr, hwaddr pa)
{
    if (env->cr[0] & CR0_CD_MASK) {
        return false;
    }
    if ((env->hflags & HF_GUEST_MASK) && (env->hflags2 & HF2_NPT_MASK) &&
        !env->vmx.nonroot &&
        (x86_ldq_phys(env_cpu(env), env->vm_hsave +
                      offsetof(struct vmcb, save.cr0)) & CR0_CD_MASK)) {
        return false;
    }
    return wb && (!mtrr || x86_mtrr_wb(env, pa));
}

static bool page_wb(CPUX86State *env, const CPUTLBEntryFull *full)
{
    return x86_bus_lock_wb(env, full->extra.x86.wb, full->extra.x86.mtrr,
                           full->phys_addr);
}

/* Whether the store of SIZE bytes at ADDR, all on one page, is to WB. */
static bool access_wb(CPUX86State *env, target_ulong addr, int size,
                      int mmu_idx, uintptr_t ra)
{
    CPUTLBEntryFull *full;
    void *host;

    probe_access_full(env, addr, size, MMU_DATA_STORE, mmu_idx, false,
                      &host, &full, ra);
    return page_wb(env, full);
}

/*
 * A locked instruction's read-modify-write of SIZE bytes at ADDR, before
 * it: whether it asserts a bus lock, splitting the first-level data
 * cache's lines (AMD64 Architecture Programmer's Manual Volume 2, 24593
 * rev. 3.46, 7.3.3) or with a memory type other than WB. The probes raise
 * the faults that the access would, before split-lock disable's #AC(0),
 * which comes before UC-lock disable's #AC(4).
 */
void HELPER(bus_lock)(CPUX86State *env, target_ulong addr, uint32_t size,
                      uint32_t mmu_idx)
{
    uintptr_t ra = GETPC();
    const CPUCacheInfo *l1d = env->cache_info.l1d_cache;
    unsigned line = l1d && l1d->line_size ? l1d->line_size : 64;
    int first = MIN(size, TARGET_PAGE_SIZE - (addr & ~TARGET_PAGE_MASK));
    bool split = (addr & (line - 1)) + size > line;
    bool split_ac = split &&
                    (env->memory_ctrl & MEMORY_CTRL_SPLIT_LOCK_DISABLE);
    bool bld = os_bld(env);
    bool vmx = vmx_bus_lock(env);
    bool uc_ac = uc_lock_disabled(env);
    bool wb;

    env->bus_lock_now = false;
    if (!split_ac && !bld && !vmx && !uc_ac) {
        return;
    }
    wb = access_wb(env, addr, first, mmu_idx, ra);
    if (first < size) {
        wb &= access_wb(env, addr + first, size - first, mmu_idx, ra);
    }
    if (split_ac) {
        raise_exception_err_ra(env, EXCP11_ALGN, 0, ra);
    }
    if (!wb && uc_ac) {
        uc_lock_fault(env, ra);
    }
    env->bus_lock_now = (bld || vmx) && (split || !wb);
}

/*
 * An implicit locked access to memory whose type is WB or not, before it:
 * implicit accesses are aligned and never split. VMX's bus-lock VM exit
 * comes after the instruction, which the access belongs to, or which
 * FETCH fetches: unless that runs alone, it runs again alone, no
 * interrupt before it, finding the bus lock pending.
 */
void x86_bus_lock_implicit(CPUX86State *env, bool wb, bool fetch,
                           uintptr_t ra)
{
    CPUState *cs = env_cpu(env);

    if (wb) {
        return;
    }
    if (uc_lock_disabled(env)) {
        uc_lock_fault(env, ra);
    }
    if (vmx_bus_lock(env) && !env->vmx.bus_lock_pending) {
        env->vmx.bus_lock_pending = true;
        cpu_set_interrupt(cs, CPU_INTERRUPT_VMX);
        qatomic_set(&cs->neg.icount_decr.u16.high, -1);
        if (ra || fetch) {
            if (ra) {
                cpu_restore_state(cs, ra);
            }
            cs->cflags_next_tb = 1 | CF_NOIRQ | cs->tcg_cflags;
            cpu_loop_exit_noexc(cs);
        }
    }
}

/* The locked update of the descriptor at the linear address ADDR. */
void x86_bus_lock_desc(CPUX86State *env, target_ulong addr, uintptr_t ra)
{
    x86_bus_lock_implicit(env, access_wb(env, addr, 1,
                                         cpu_mmu_index_kernel(env), ra),
                          false, ra);
}

/*
 * At the end of the locked instruction, whose bus lock's #DB is a trap
 * that clears DR6.BLD as it is delivered: with TF's single-step trap and
 * the breakpoints it hit, after VMX's bus-lock VM exit or monitor trap
 * flag VM exit, which leave them pending (Intel SDM 325462-093 Vol. 3C,
 * 28.2 and 28.5.2).
 */
void HELPER(bus_lock_done)(CPUX86State *env)
{
    uint32_t traps;

    if (!env->bus_lock_now) {
        return;
    }
    env->bus_lock_now = false;
    traps = (os_bld(env) ? DR6_BLD : 0) | x86_step_trap(env, false);
    do_end_instruction(env);
    if (vmx_bus_lock(env)) {
        x86_vmx_bus_lock_exit(env, traps);
    }
    if (x86_vmx_mtf(env)) {
        x86_vmx_mtf_step(env, traps);
    }
    raise_debug_exception(env, traps | hw_breakpoint_hits(env, NULL), 0);
}
