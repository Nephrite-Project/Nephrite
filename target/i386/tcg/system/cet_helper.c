/*
 * x86 control-flow enforcement for TCG (system emulator)
 *
 * Control-flow enforcement's shadow stacks (Intel SDM 325462-093 Vol. 1,
 * 18.2; AMD64 Architecture Programmer's Manual Volume 2, 24593 rev. 3.45,
 * 18): SSP is env->guest_ssp, and shadow-stack accesses go through MMU
 * indexes of their own, whose translations allow only shadow-stack pages
 * (Intel SDM 325462-093 Vol. 3A, 5.6.1). Also what helpers do of indirect
 * branch tracking: far transfers and legacy compatibility treatment (Intel
 * SDM 325462-093 Vol. 1, 18.3).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "accel/tcg/cpu-ldst.h"
#include "accel/tcg/cpu-loop.h"
#include "tcg/helper-tcg.h"
#include "../seg_helper.h"

/* The busy bit of a supervisor shadow-stack token. */
#define SHSTK_BUSY 1ULL

static int shstk_mmu_index(CPUX86State *env, bool user)
{
    return (user ? MMU_SS_USER_IDX : MMU_SS_SUP_IDX) +
           (env->hflags & HF_GUEST_MASK ? MMU_SS_GUEST : 0);
}

static uint64_t shstk_ldq(CPUX86State *env, target_ulong addr, bool user,
                          uintptr_t ra)
{
    return cpu_ldq_le_mmuidx_ra(env, addr, shstk_mmu_index(env, user), ra);
}

static uint32_t shstk_ldl(CPUX86State *env, target_ulong addr, bool user,
                          uintptr_t ra)
{
    return cpu_ldl_le_mmuidx_ra(env, addr, shstk_mmu_index(env, user), ra);
}

static void shstk_stq(CPUX86State *env, target_ulong addr, uint64_t val,
                      bool user, uintptr_t ra)
{
    cpu_stq_le_mmuidx_ra(env, addr, val, shstk_mmu_index(env, user), ra);
}

static void shstk_stl(CPUX86State *env, target_ulong addr, uint32_t val,
                      bool user, uintptr_t ra)
{
    cpu_stl_le_mmuidx_ra(env, addr, val, shstk_mmu_index(env, user), ra);
}

/*
 * shadow_stack_lock_cmpxchg8B: a locked shadow-stack load of the 8 bytes at
 * addr, then an unlocking store of new where they are old, else of what was
 * read; returns what was read.
 */
static uint64_t shstk_cmpxchgq(CPUX86State *env, target_ulong addr,
                               uint64_t old, uint64_t new, bool user,
                               uintptr_t ra)
{
    MemOpIdx oi = make_memop_idx(MO_LEUQ, shstk_mmu_index(env, user));

    return cpu_atomic_cmpxchgq_le_mmu(env, addr, old, new, oi, ra);
}

/* Whether 64-bit mode is on: IA32_EFER.LMA and CS.L. */
static bool shstk_code64(CPUX86State *env)
{
    return env->hflags & HF_CS64_MASK;
}

/*
 * The shadow-stack pointer arithmetic of SSP: 32-bit outside 64-bit mode
 * (Intel SDM 325462-093 Vol. 1, 18.2.1).
 */
static uint64_t shstk_wrap(CPUX86State *env, uint64_t ssp)
{
    return shstk_code64(env) ? ssp : (uint32_t)ssp;
}

static int shstk_cpl(CPUX86State *env)
{
    return env->hflags & HF_CPL_MASK;
}

static G_NORETURN void raise_cp(CPUX86State *env, int code, uintptr_t ra)
{
    raise_exception_err_ra(env, EXCP15_CP, code, ra);
}

uint64_t x86_la_adjust(CPUX86State *env, uint64_t addr)
{
    int shift = env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_LA57 ? 7 : 16;

    return (int64_t)(addr << shift) >> shift;
}

void x86_shstk_save_user(CPUX86State *env)
{
    env->pl3_ssp = env->hflags & HF_LMA_MASK ?
                   x86_la_adjust(env, env->guest_ssp) : env->guest_ssp;
}

/* An SSP to load: 32-bit outside 64-bit mode, else canonical. */
static bool shstk_ssp_valid(CPUX86State *env, uint64_t ssp, bool to64)
{
    return to64 ? x86_canonical(env, ssp, true) : !(ssp >> 32);
}

/*
 * Pushes the 8-byte CS, LIP, and SSP of a far transfer's frame onto the
 * shadow stack at *ssp.
 */
static void shstk_push_frame(CPUX86State *env, uint64_t *ssp, uint64_t cs,
                             uint64_t lip, uint64_t old_ssp, bool user,
                             uintptr_t ra)
{
    shstk_stq(env, *ssp - 8, cs, user, ra);
    shstk_stq(env, *ssp - 16, lip, user, ra);
    shstk_stq(env, *ssp - 24, old_ssp, user, ra);
    *ssp -= 24;
}

/*
 * The frame of a far transfer that keeps its shadow stack, from new_ssp:
 * past 4 bytes of 0 at the next 8-byte boundary, the old CS, LIP, and SSP
 * (Intel SDM 325462-093 Vol. 2A, CALL and INT n).
 */
static void shstk_push_aligned(CPUX86State *env, uint64_t new_ssp,
                               uint32_t cs, uint64_t lip, bool user,
                               uintptr_t ra)
{
    uint64_t ssp = new_ssp & ~7ULL;

    shstk_stl(env, new_ssp - 4, 0, user, ra);
    shstk_push_frame(env, &ssp, cs, lip, env->guest_ssp, user, ra);
    env->guest_ssp = ssp;
}

/*
 * Marks the supervisor shadow-stack token at addr busy: false where it is
 * not a free token for addr (Intel SDM 325462-093 Vol. 1, 18.2.3).
 */
bool x86_shstk_acquire(CPUX86State *env, uint64_t addr, uintptr_t ra)
{
    return shstk_cmpxchgq(env, addr, addr, addr | SHSTK_BUSY, false, ra) ==
           addr;
}

/* Frees the busy supervisor shadow-stack token at addr, if it is one. */
void x86_shstk_release(CPUX86State *env, uint64_t addr, uintptr_t ra)
{
    shstk_cmpxchgq(env, addr, addr | SHSTK_BUSY, addr, false, ra);
}

/*
 * A switch to the shadow stack whose supervisor token is at new_ssp, which
 * the CS, LIP, and SSP of the transfer's origin go on where push is set:
 * #GP(0) where the token is misaligned, the frame and it are not in one
 * aligned 32-byte block, a 32-bit SSP is not, or the token is not free.
 * Intel's processors check the block whether or not the frame goes on
 * (Intel SDM 325462-093 Vol. 2A, CALL and INT n), AMD's only where it does
 * (AMD64 Architecture Programmer's Manual Volume 2, 24593 rev. 3.46,
 * 18.6.4).
 */
static void shstk_switch_in(CPUX86State *env, uint64_t new_ssp, bool to64,
                            bool push, uint32_t cs, uint64_t lip,
                            uintptr_t ra)
{
    bool block = push || !IS_AMD_CPU(env);
    uint64_t ssp = new_ssp;

    if ((new_ssp & 7) ||
        (block && (new_ssp & ~0x1fULL) != ((new_ssp - 24) & ~0x1fULL)) ||
        (!to64 && (new_ssp >> 32)) || !x86_shstk_acquire(env, new_ssp, ra)) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }
    if (push) {
        shstk_push_frame(env, &ssp, cs, lip, env->guest_ssp, false, ra);
    }
    env->guest_ssp = ssp;
}

void x86_shstk_far_call(CPUX86State *env, bool to64, uint32_t cs,
                        uint64_t lip, uintptr_t ra)
{
    if (!to64 && (env->guest_ssp >> 32)) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }
    shstk_push_aligned(env, env->guest_ssp, cs, lip, shstk_cpl(env) == 3,
                       ra);
}

void x86_shstk_enter(CPUX86State *env, int cpl, int dpl, int ist, bool to64,
                     uint32_t cs, uint64_t lip, uintptr_t ra)
{
    /*
     * The handler runs outside virtual-8086 mode, which shadow stacks are
     * enabled in, or not, as at CPL dpl elsewhere.
     */
    bool new_on = (env->cr[4] & CR4_CET_MASK) &&
                  ((dpl == 3 ? env->u_cet : env->s_cet) & CET_SH_STK_EN);
    uint64_t new_ssp;

    if (dpl < cpl) {
        if (x86_shstk_enabled(env, cpl) && cpl == 3) {
            x86_shstk_save_user(env);
        }
        if (!new_on) {
            return;
        }
        new_ssp = *x86_pl_ssp(env, dpl);
#ifdef TARGET_X86_64
        if (ist && (env->hflags & HF_LMA_MASK)) {
            new_ssp = cpu_ldq_kernel_ra(env, env->int_ssp_table + ist * 8,
                                        ra);
        }
#endif
        shstk_switch_in(env, new_ssp, to64, cpl != 3, cs, lip, ra);
        return;
    }
    if (!x86_shstk_enabled(env, cpl)) {
        return;
    }
    new_ssp = env->guest_ssp;
#ifdef TARGET_X86_64
    /*
     * An IA-32e mode gate with an IST index switches to the shadow stack of
     * the interrupt shadow-stack table's entry, whose token it acquires.
     */
    if (ist && (env->hflags & HF_LMA_MASK)) {
        new_ssp = cpu_ldq_kernel_ra(env, env->int_ssp_table + ist * 8, ra);
        if ((new_ssp & 7) ||
            (new_ssp & ~0x1fULL) != ((new_ssp - 24) & ~0x1fULL) ||
            !x86_shstk_acquire(env, new_ssp, ra)) {
            raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
        }
    }
#endif
    shstk_push_aligned(env, new_ssp, cs, lip, cpl == 3, ra);
}

/*
 * Pops the CS, LIP, and SSP of a far transfer's frame off the shadow stack
 * at *ssp: #CP(FAR-RET/IRET) where the CS and LIP returned to differ, or the
 * SSP is not 4-byte aligned.
 */
static uint64_t shstk_pop_frame(CPUX86State *env, uint64_t *ssp, uint32_t cs,
                                uint64_t lip, bool user, uintptr_t ra)
{
    uint64_t ss_cs = shstk_ldq(env, *ssp + 16, user, ra);
    uint64_t ss_lip = shstk_ldq(env, *ssp + 8, user, ra);
    uint64_t prev = shstk_ldq(env, *ssp, user, ra);

    *ssp += 24;
    if (ss_cs != cs || ss_lip != lip || (prev & 3)) {
        raise_cp(env, CP_FAR_RET_IRET, ra);
    }
    return prev;
}

void x86_shstk_return(CPUX86State *env, X86ShstkReturn *r, bool iret,
                      int cpl, int rpl, uint32_t cs, uint64_t lip, bool to64,
                      uintptr_t ra)
{
    bool old_on = x86_shstk_enabled(env, cpl);
    uint64_t ssp = env->guest_ssp;
    uint64_t new_ssp = 0;
    bool popped = false;

    *r = (X86ShstkReturn){ 0 };
    if (old_on) {
        if (ssp & 7) {
            raise_cp(env, CP_FAR_RET_IRET, ra);
        }
        if (rpl == cpl || rpl != 3) {
            new_ssp = shstk_pop_frame(env, &ssp, cs, lip, cpl == 3, ra);
            popped = true;
        }
    }
    if (rpl == cpl) {
        if (!old_on) {
            return;
        }
        if (!shstk_ssp_valid(env, new_ssp, to64)) {
            raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
        }
        /*
         * An IA-32e mode IRET frees the token of a shadow stack that the
         * event's IST index switched to.
         */
        if (iret && (env->hflags & HF_LMA_MASK) && new_ssp != ssp) {
            r->release = true;
            r->token = ssp;
        }
        r->set = true;
        r->ssp = new_ssp;
        return;
    }
    /* To an outer privilege level, which takes PL3_SSP if it is 3. */
    if (x86_shstk_enabled(env, rpl)) {
        if (rpl == 3) {
            new_ssp = env->pl3_ssp;
            popped = true;
        }
        if (popped) {
            if (!shstk_ssp_valid(env, new_ssp, to64)) {
                raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
            }
            r->set = true;
            r->ssp = new_ssp;
        }
    }
    if (old_on) {
        r->release = true;
        r->token = ssp;
    }
}

/*
 * Carries out the shadow-stack work of a return once nothing else can
 * fault: what was the old shadow stack's token is freed after the change
 * of privilege level.
 */
void x86_shstk_return_commit(CPUX86State *env, const X86ShstkReturn *r,
                             uintptr_t ra)
{
    if (r->release) {
        x86_shstk_release(env, r->token, ra);
    }
    if (r->set) {
        env->guest_ssp = r->ssp;
    }
}

void x86_shstk_task_pop(CPUX86State *env, X86ShstkTask *t, uintptr_t ra)
{
    uint64_t ssp = env->guest_ssp;
    int cpl = shstk_cpl(env);

    t->cs = shstk_ldq(env, ssp + 16, cpl == 3, ra);
    t->lip = shstk_ldq(env, ssp + 8, cpl == 3, ra);
    t->ssp = shstk_ldq(env, ssp, cpl == 3, ra);
    env->guest_ssp = ssp + 24;
}

void x86_shstk_task_push(CPUX86State *env, const X86ShstkTask *t,
                         uintptr_t ra)
{
    uint64_t ssp = env->guest_ssp;

    shstk_push_frame(env, &ssp, t->cs, t->lip, t->ssp, shstk_cpl(env) == 3,
                     ra);
    env->guest_ssp = ssp;
}

void x86_shstk_push(CPUX86State *env, uint64_t val, uintptr_t ra)
{
    uint64_t ssp = env->guest_ssp - 8;

    shstk_stq(env, ssp, val, shstk_cpl(env) == 3, ra);
    env->guest_ssp = ssp;
}

void x86_shstk_pop_check(CPUX86State *env, uint64_t val, int code,
                         uintptr_t ra)
{
    uint64_t ssp = env->guest_ssp;

    if (shstk_ldq(env, ssp, shstk_cpl(env) == 3, ra) != val) {
        raise_cp(env, code, ra);
    }
    env->guest_ssp = ssp + 8;
}

#ifdef TARGET_X86_64
/*
 * FRED event delivery's frame on the supervisor shadow stack at *ssp (Intel
 * SDM 325462-093 Vol. 3A, 8.3.2.2): 4 bytes of zeros below *ssp, then, from
 * its 8-byte boundary down, the augmented CS, the LIP, and the old SSP.
 */
void x86_shstk_fred_push(CPUX86State *env, uint64_t *ssp, uint64_t cs,
                         uint64_t lip, uint64_t old_ssp)
{
    uint64_t new_ssp = *ssp & ~7ULL;

    shstk_stl(env, *ssp - 4, 0, false, 0);
    shstk_push_frame(env, &new_ssp, cs, lip, old_ssp, false, 0);
    *ssp = new_ssp;
}

/* ERETS's pops of that frame (Intel SDM 325462-093 Vol. 2A, ERETS). */
void x86_shstk_fred_pop(CPUX86State *env, uint64_t *ssp, uint64_t *old_ssp,
                        uint64_t *lip, uint64_t *cs, uintptr_t ra)
{
    *old_ssp = shstk_ldq(env, *ssp, false, ra);
    *lip = shstk_ldq(env, *ssp + 8, false, ra);
    *cs = shstk_ldq(env, *ssp + 16, false, ra);
    *ssp += 24;
}
#endif

void x86_ibt_far(CPUX86State *env, int cpl)
{
    uint64_t *cet = cpl == 3 ? &env->u_cet : &env->s_cet;

    if ((env->cr[4] & CR4_CET_MASK) && (env->cr[0] & CR0_PE_MASK) &&
        !(env->eflags & VM_MASK) && (*cet & CET_ENDBR_EN)) {
        *cet = (*cet & ~CET_SUPPRESS) | CET_WAIT_ENDBR;
    }
}

/*
 * An instruction that is not an ENDBRANCH where the tracker waits for one:
 * #CP(ENDBRANCH), but with legacy compatibility treatment where the legacy
 * code page bitmap marks the instruction's page, whose code then runs with
 * the tracker idle and, unless SUPPRESS_DIS, suppressed (Intel SDM
 * 325462-093 Vol. 1, 18.3.6).
 */
void HELPER(ibt_missing)(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);
    uint64_t *cet;
    uint64_t la, addr;
    uint8_t bits;

    cpu_restore_state(cs, GETPC());
    cet = shstk_cpl(env) == 3 ? &env->u_cet : &env->s_cet;
    if (!(*cet & CET_LEG_IW_EN)) {
        raise_cp(env, CP_ENDBRANCH, 0);
    }
    /* The bitmap has a bit for each 4-KByte page of linear addresses. */
    if (shstk_code64(env)) {
        la = env->eip;
        addr = (la & (env->cr[4] & CR4_LA57_MASK ? MAKE_64BIT_MASK(0, 57)
                                                  : MAKE_64BIT_MASK(0, 48)))
               >> 15;
    } else {
        la = (uint32_t)(env->segs[R_CS].base + env->eip);
        addr = la >> 15;
    }
    addr += *cet & ~0xfffULL;
    if (!(env->hflags & HF_LMA_MASK)) {
        addr = (uint32_t)addr;
    }
    bits = cpu_ldub_mmuidx_ra(env, addr, cpu_mmu_index(cs, false), 0);
    if (!(bits & (1 << ((la >> 12) & 7)))) {
        raise_cp(env, CP_ENDBRANCH, 0);
    }
    *cet &= ~(CET_WAIT_ENDBR | CET_SUPPRESS);
    if (!(*cet & CET_SUPPRESS_DIS)) {
        *cet |= CET_SUPPRESS;
    }
    /* The instruction runs again, translated with the new state. */
    cpu_loop_exit(cs);
}

/*
 * The shadow-stack management instructions (Intel SDM 325462-093 Vol. 2A
 * to 2D): #UD unless shadow stacks are enabled at the CPL, or for those
 * of supervisor shadow-stack tokens at CPL 0, which FRED transitions
 * disable, then #GP(0) at other CPLs.
 */
static void shstk_check(CPUX86State *env, uintptr_t ra)
{
    if (!x86_shstk_enabled(env, shstk_cpl(env))) {
        raise_exception_ra(env, EXCP06_ILLOP, ra);
    }
}

static void shstk_check_token_insn(CPUX86State *env, uintptr_t ra)
{
    if (!(env->cr[4] & CR4_CET_MASK) || !(env->cr[0] & CR0_PE_MASK) ||
        (env->eflags & VM_MASK) || !(env->s_cet & CET_SH_STK_EN) ||
        (env->cr[4] & CR4_FRED_MASK)) {
        raise_exception_ra(env, EXCP06_ILLOP, ra);
    }
    if (shstk_cpl(env)) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }
}

/*
 * A near CALL's push of the return address: 8 bytes for a 64-bit one, else
 * 4 with IP zero-extended (Intel SDM 325462-093 Vol. 2A, CALL).
 */
void HELPER(shstk_call)(CPUX86State *env, target_ulong ret, uint32_t size)
{
    uint64_t ssp = shstk_wrap(env, env->guest_ssp - (size == 8 ? 8 : 4));
    bool user = shstk_cpl(env) == 3;

    if (size == 8) {
        shstk_stq(env, ssp, ret, user, GETPC());
    } else {
        shstk_stl(env, ssp, size == 2 ? (uint16_t)ret : ret, user, GETPC());
    }
    env->guest_ssp = ssp;
}

/*
 * A near RET's pop, which must match the return address: #CP(NEAR-RET)
 * otherwise (Intel SDM 325462-093 Vol. 2B, RET).
 */
void HELPER(shstk_ret)(CPUX86State *env, target_ulong ret, uint32_t size)
{
    uint64_t ssp = env->guest_ssp;
    bool user = shstk_cpl(env) == 3;
    uint64_t val;

    if (size == 8) {
        val = shstk_ldq(env, ssp, user, GETPC());
    } else {
        val = shstk_ldl(env, ssp, user, GETPC());
        ret = (uint32_t)ret;
    }
    if (val != ret) {
        raise_cp(env, CP_NEAR_RET, GETPC());
    }
    env->guest_ssp = shstk_wrap(env, ssp + (size == 8 ? 8 : 4));
}

void HELPER(incssp)(CPUX86State *env, target_ulong src, uint32_t size64)
{
    int size = size64 ? 8 : 4;
    unsigned range = src & 0xff;
    bool user = shstk_cpl(env) == 3;
    uint64_t ssp = env->guest_ssp;

    shstk_check(env, GETPC());
    if (size == 8) {
        shstk_ldq(env, ssp, user, GETPC());
        if (range) {
            shstk_ldq(env, ssp + 8 * (range - 1), user, GETPC());
        }
    } else {
        shstk_ldl(env, ssp, user, GETPC());
        if (range) {
            shstk_ldl(env, shstk_wrap(env, ssp + 4 * (range - 1)), user,
                      GETPC());
        }
    }
    env->guest_ssp = shstk_wrap(env, ssp + range * size);
}

/* A NOP with shadow stacks off, else SSP into the register. */
target_ulong HELPER(rdssp)(CPUX86State *env, target_ulong dest,
                           uint32_t size64)
{
    if (!x86_shstk_enabled(env, shstk_cpl(env))) {
        return dest;
    }
    return size64 ? env->guest_ssp : (uint32_t)env->guest_ssp;
}

void HELPER(saveprevssp)(CPUX86State *env)
{
    bool user = shstk_cpl(env) == 3;
    bool l = shstk_code64(env);
    uint64_t ssp = env->guest_ssp;
    uint64_t token, old_ssp, val;

    shstk_check(env, GETPC());
    if (ssp & 7) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }
    token = shstk_ldq(env, ssp, user, GETPC());
    ssp = shstk_wrap(env, ssp + 8);
    /* CF tells of an alignment hole, which only 32-bit SSPs can have. */
    if (cpu_cc_compute_all(env) & CC_C) {
        if (l || shstk_ldl(env, ssp, user, GETPC())) {
            raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
        }
        ssp = shstk_wrap(env, ssp + 4);
    }
    if (!(token & 2) || (!l && (token >> 32))) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }
    old_ssp = token & ~3ULL;
    val = old_ssp | l;
    shstk_stl(env, shstk_wrap(env, old_ssp - 4), 0, user, GETPC());
    old_ssp &= ~7ULL;
    shstk_stq(env, shstk_wrap(env, old_ssp - 8), val, user, GETPC());
    env->guest_ssp = ssp;
}

/* RSTORSSP, which returns its flags: CF where the token had bit 2 set. */
target_ulong HELPER(rstorssp)(CPUX86State *env, target_ulong addr)
{
    bool user = shstk_cpl(env) == 3;
    bool l = shstk_code64(env);
    uint64_t prev = env->guest_ssp | l | 2;
    uint64_t token, read;
    bool fault;

    shstk_check(env, GETPC());
    if (addr & 7) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }
    /*
     * The token is replaced by a previous-SSP token if it is a restore
     * token for addr in this mode, else written back as it was.
     */
    token = shstk_ldq(env, addr, user, GETPC());
    for (;;) {
        fault = (token & 3) != l || (!l && (token >> 32)) ||
                (((token & ~1ULL) - 8) & ~7ULL) != addr;
        read = shstk_cmpxchgq(env, addr, token, fault ? token : prev, user,
                              GETPC());
        if (read == token) {
            break;
        }
        token = read;
    }
    if (fault) {
        raise_cp(env, CP_RSTORSSP, GETPC());
    }
    env->guest_ssp = addr;
    return token & 4 ? CC_C : 0;
}

void HELPER(setssbsy)(CPUX86State *env)
{
    uint64_t addr = env->pl0_ssp;

    shstk_check_token_insn(env, GETPC());
    if (addr & 7) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }
    if (!x86_shstk_acquire(env, addr, GETPC())) {
        raise_cp(env, CP_SETSSBSY, GETPC());
    }
    env->guest_ssp = addr;
}

/* CLRSSBSY, which returns its flags: CF where the token was not busy. */
target_ulong HELPER(clrssbsy)(CPUX86State *env, target_ulong addr)
{
    bool invalid;

    shstk_check_token_insn(env, GETPC());
    if (addr & 7) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }
    invalid = shstk_cmpxchgq(env, addr, addr | SHSTK_BUSY, addr, false,
                             GETPC()) != (addr | SHSTK_BUSY);
    env->guest_ssp = 0;
    return invalid ? CC_C : 0;
}

static void shstk_write(CPUX86State *env, target_ulong addr, target_ulong val,
                        uint32_t size64, bool user, uintptr_t ra)
{
    if (addr & (size64 ? 7 : 3)) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, ra);
    }
    if (size64) {
        shstk_stq(env, addr, val, user, ra);
    } else {
        shstk_stl(env, addr, val, user, ra);
    }
}

void HELPER(wrss)(CPUX86State *env, target_ulong addr, target_ulong val,
                  uint32_t size64)
{
    int cpl = shstk_cpl(env);

    shstk_check(env, GETPC());
    if (!((cpl == 3 ? env->u_cet : env->s_cet) & CET_WR_SHSTK_EN)) {
        raise_exception_ra(env, EXCP06_ILLOP, GETPC());
    }
    shstk_write(env, addr, val, size64, cpl == 3, GETPC());
}

/* WRUSS, whose shadow-stack store is a user access though at CPL 0. */
void HELPER(wruss)(CPUX86State *env, target_ulong addr, target_ulong val,
                   uint32_t size64)
{
    if (!(env->cr[4] & CR4_CET_MASK) || !(env->cr[0] & CR0_PE_MASK) ||
        (env->eflags & VM_MASK)) {
        raise_exception_ra(env, EXCP06_ILLOP, GETPC());
    }
    if (shstk_cpl(env)) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }
    shstk_write(env, addr, val, size64, true, GETPC());
}
