/*
 * x86 bus locks for TCG (system emulator)
 *
 * A locked read-modify-write access asserts a bus lock where it splits
 * cache lines or its memory type is not WB (Intel SDM 325462-093 Vol. 3A,
 * 11.1.2; AMD64 Architecture Programmer's Manual Volume 2, 24593 rev. 3.46,
 * 7.3.3). OS bus-lock detection then raises a trap-like #DB after an
 * instruction at CPL > 0 that asserted one (Intel SDM 325462-093 Vol. 3B,
 * 20.3.1.6; AMD64 Architecture Programmer's Manual Volume 2, 24593 rev.
 * 3.46, 13.1.3.6).
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
#include "accel/tcg/probe.h"
#include "tcg/helper-tcg.h"

bool x86_bus_lock_checks;

void x86_bus_lock_watch(CPUX86State *env)
{
    if (!qatomic_read(&x86_bus_lock_checks)) {
        qatomic_set(&x86_bus_lock_checks, true);
        queue_tb_flush(env_cpu(env));
    }
}

/*
 * Whether bus locks matter to the processor now: OS bus-lock detection
 * matters at CPL > 0.
 */
static bool bus_lock_watched(CPUX86State *env)
{
    return (env->debugctl & DEBUGCTL_BLD) && (env->hflags & HF_CPL_MASK);
}

/*
 * Whether the page of FULL is WB: CR0.CD makes accesses uncacheable, under
 * nested paging the host's as well as the guest's (Intel SDM 325462-093
 * Vol. 3A, 14.5.2 and Vol. 3C, 31.3.7.2; AMD64 Architecture Programmer's
 * Manual Volume 2, 24593 rev. 3.46, 7.4 and 15.25.9).
 */
static bool page_wb(CPUX86State *env, const CPUTLBEntryFull *full)
{
    if (env->cr[0] & CR0_CD_MASK) {
        return false;
    }
    if ((env->hflags & HF_GUEST_MASK) && (env->hflags2 & HF2_NPT_MASK) &&
        (x86_ldq_phys(env_cpu(env), env->vm_hsave +
                      offsetof(struct vmcb, save.cr0)) & CR0_CD_MASK)) {
        return false;
    }
    return full->extra.x86.wb &&
           (!full->extra.x86.mtrr || x86_mtrr_wb(env, full->phys_addr));
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
 * the faults that the access would.
 */
void HELPER(bus_lock)(CPUX86State *env, target_ulong addr, uint32_t size,
                      uint32_t mmu_idx)
{
    uintptr_t ra = GETPC();
    const CPUCacheInfo *l1d = env->cache_info.l1d_cache;
    unsigned line = l1d && l1d->line_size ? l1d->line_size : 64;
    int first = MIN(size, TARGET_PAGE_SIZE - (addr & ~TARGET_PAGE_MASK));
    bool wb;

    env->bus_lock_now = false;
    if (!bus_lock_watched(env)) {
        return;
    }
    wb = access_wb(env, addr, first, mmu_idx, ra);
    if (first < size) {
        wb &= access_wb(env, addr + first, size - first, mmu_idx, ra);
    }
    env->bus_lock_now = (addr & (line - 1)) + size > line || !wb;
}

/*
 * At the end of the locked instruction, whose bus lock's #DB is a trap
 * that clears DR6.BLD as it is delivered: with TF's single-step trap and
 * the breakpoints it hit, after VMX's monitor trap flag VM exit, which
 * leaves them pending (Intel SDM 325462-093 Vol. 3C, 28.5.2).
 */
void HELPER(bus_lock_done)(CPUX86State *env)
{
    uint32_t traps;

    if (!env->bus_lock_now) {
        return;
    }
    env->bus_lock_now = false;
    traps = DR6_BLD | x86_step_trap(env, false);
    do_end_instruction(env);
    if (x86_vmx_mtf(env)) {
        x86_vmx_mtf_step(env, traps);
    }
    raise_debug_exception(env, traps | hw_breakpoint_hits(env, NULL), 0);
}
