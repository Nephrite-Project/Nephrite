/*
 * x86 performance monitoring for TCG (system emulator)
 *
 * Intel's architectural performance monitoring, version 2 (Intel SDM
 * 325462-093 Vol. 3B, 22.2.1 and 22.2.2), and AMD's core performance
 * counters (AMD64 Architecture Programmer's Manual Volume 2, 24593 rev.
 * 3.45, 13.2).  The counters count instructions retired, cycles at one
 * instruction a cycle, branch instructions retired, and as the mispredicted
 * ones near indirect jumps and calls; on AMD also, as both, the far control
 * transfers and the deliveries of exceptions and interrupts (PPR for AMD
 * Family 17h Model 20h, 55772 rev. 3.08, 2.1.14.3.5).
 *
 * Generated code counts these events per bucket of CPL > 0 and SVM guest
 * mode: a TB adds its instruction count at its start and each branch
 * instruction its branch, and a state restore takes back the instructions
 * that the TB did not complete.  A counter derives its value from these
 * totals whenever it is read or reconfigured, and whenever a TB starts in a
 * bucket past its limit, the point by which some counter may overflow.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/host-utils.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/translation-block.h"
#include "hw/i386/apic.h"
#include "tcg/helper-tcg.h"

#define PMU_MASK MAKE_64BIT_MASK(0, X86_PMU_WIDTH)

/*
 * IA32_PERFEVTSELx (Intel SDM 325462-093 Vol. 3B, Figure 22-1), whose bits
 * 63:32 and 21, AnyThread, version 2 does not have, and AMD's PerfEvtSeln
 * (AMD64 Architecture Programmer's Manual Volume 2, 24593 rev. 3.45, Figure
 * 13-11), whose other bits read as zero.
 */
#define EVTSEL_USR (1ULL << 16)
#define EVTSEL_OS (1ULL << 17)
#define EVTSEL_INT (1ULL << 20)
#define EVTSEL_EN (1ULL << 22)
#define EVTSEL_INV (1ULL << 23)
#define INTEL_EVTSEL_RESERVED 0xffffffff00200000ULL
#define AMD_EVTSEL_DEFINED 0x0000030fffd7ffffULL
#define AMD_EVTSEL_GUEST_ONLY (1ULL << 40)
#define AMD_EVTSEL_HOST_ONLY (1ULL << 41)

/* IA32_FIXED_CTR_CTRL, 4 bits a counter: OS, USR, AnyThread, and PMI. */
#define FIXED_CTRL_DEFINED 0xbbbULL

/* The counters' bits in the global MSRs, and the status's others. */
#define GLOBAL_COUNTERS (MAKE_64BIT_MASK(0, X86_PMU_GP_COUNTERS) | \
                         MAKE_64BIT_MASK(32, MAX_FIXED_COUNTERS))
#define GLOBAL_STATUS_OTHERS 0xc000000000000000ULL

/* The buckets of CPL 0 and CPL > 0, of host and guest mode. */
#define BUCKETS_OS 0x5
#define BUCKETS_USR 0xa
#define BUCKETS_HOST 0x3
#define BUCKETS_GUEST 0xc

/* AMD's core counters with PerfCtrExtCore, and its legacy ones. */
#define AMD_CORE_COUNTERS 6
#define AMD_LEGACY_COUNTERS 4

bool x86_pmu_enabled(CPUX86State *env)
{
    return env_archcpu(env)->enable_pmu;
}

unsigned x86_pmu_bucket(uint32_t hflags)
{
    return ((hflags & HF_CPL_MASK) != 0) | (hflags & HF_GUEST_MASK ? 2 : 0);
}

static unsigned pmu_counters(CPUX86State *env)
{
    if (IS_INTEL_CPU(env)) {
        return X86_PMU_COUNTERS;
    }
    return env->features[FEAT_8000_0001_ECX] & CPUID_EXT3_PERFCORE ?
           AMD_CORE_COUNTERS : AMD_LEGACY_COUNTERS;
}

/* Counter C: Intel's general-purpose and then fixed ones, or AMD's. */
static uint64_t *pmu_value(CPUX86State *env, unsigned c)
{
    if (c < X86_PMU_GP_COUNTERS) {
        return &env->msr_gp_counters[c];
    }
    return &env->msr_fixed_counters[c - X86_PMU_GP_COUNTERS];
}

static uint64_t pmu_global_bit(unsigned c)
{
    if (c < X86_PMU_GP_COUNTERS) {
        return 1ULL << c;
    }
    return 1ULL << (32 + c - X86_PMU_GP_COUNTERS);
}

/*
 * The events counter C has counted by now, without the instruction that
 * accesses the PMU, which has not retired yet.
 */
static uint64_t pmu_events(CPUX86State *env, const X86PMUCounter *ctr)
{
    X86PMUState *p = &env->pmu;
    unsigned cur = x86_pmu_bucket(env->hflags);
    uint64_t events = 0;

    for (unsigned b = 0; b < X86_PMU_BUCKETS; b++) {
        uint64_t insns = p->insns[b] - (b == cur ? p->unretired : 0);

        if (!(ctr->buckets & (1 << b))) {
            continue;
        }
        events += (uint64_t)(int64_t)ctr->insns * insns +
                  (uint64_t)(int64_t)ctr->branches * p->branches[b] +
                  (uint64_t)(int64_t)ctr->mispredicts * p->mispredicts[b];
    }
    return events;
}

/*
 * The instructions that the totals have counted but that did not retire:
 * those of a TB that a state restore cut short, and a software interrupt
 * that was not delivered.
 */
static void pmu_take_back(CPUX86State *env)
{
    X86PMUState *p = &env->pmu;

    if (p->fix_pending) {
        p->insns[p->fix_bucket] -= p->fix_insns;
        p->branches[p->fix_bucket] -= p->fix_branches;
        p->mispredicts[p->fix_bucket] -= p->fix_mispredicts;
        p->fix_pending = false;
    }
    if (p->soft_int) {
        p->insns[p->soft_int - 1]--;
        p->branches[p->soft_int - 1]--;
        p->soft_int = 0;
    }
}

/*
 * Each bucket's limit: the instruction total by which a counter counting in
 * it could overflow, its share of the events it has left to count before
 * then.
 */
static void pmu_set_limits(CPUX86State *env)
{
    X86PMUState *p = &env->pmu;
    unsigned cur = x86_pmu_bucket(env->hflags);
    uint64_t room[X86_PMU_BUCKETS];

    for (unsigned b = 0; b < X86_PMU_BUCKETS; b++) {
        room[b] = UINT64_MAX;
    }
    for (unsigned c = 0; c < pmu_counters(env); c++) {
        const X86PMUCounter *ctr = &p->ctr[c];
        uint64_t left = PMU_MASK + 1 - *pmu_value(env, c);
        uint64_t share;

        if (!ctr->buckets) {
            continue;
        }
        share = DIV_ROUND_UP(left, ctpop8(ctr->buckets));
        for (unsigned b = 0; b < X86_PMU_BUCKETS; b++) {
            if (ctr->buckets & (1 << b)) {
                room[b] = MIN(room[b], share);
            }
        }
    }
    for (unsigned b = 0; b < X86_PMU_BUCKETS; b++) {
        uint64_t insns = p->insns[b] - (b == cur ? p->unretired : 0);

        p->limit[b] = insns > UINT64_MAX - room[b] ? UINT64_MAX :
                      insns + room[b];
    }
}

/*
 * An overflow's performance monitoring interrupt, through the local APIC's
 * LVT performance counter entry, which on Intel processors the delivery
 * masks (Intel SDM 325462-093 Vol. 3A, 13.5.1).
 */
static void pmu_raise_pmi(CPUX86State *env)
{
    APICCommonState *apic = env_archcpu(env)->apic_state;

    if (apic) {
        BQL_LOCK_GUARD();

        apic_deliver_pmi(apic, IS_INTEL_CPU(env));
    }
}

/* Bring the counters' values up to the totals. */
static void pmu_update(CPUX86State *env)
{
    X86PMUState *p = &env->pmu;
    bool pmi = false;

    pmu_take_back(env);
    for (unsigned c = 0; c < pmu_counters(env); c++) {
        X86PMUCounter *ctr = &p->ctr[c];
        uint64_t events, value;

        if (!ctr->buckets) {
            continue;
        }
        events = pmu_events(env, ctr);
        value = *pmu_value(env, c) + (events - ctr->events);
        ctr->events = events;
        if (value > PMU_MASK) {
            if (IS_INTEL_CPU(env)) {
                env->msr_global_status |= pmu_global_bit(c);
            }
            pmi |= ctr->pmi;
        }
        *pmu_value(env, c) = value & PMU_MASK;
    }
    if (pmi) {
        pmu_raise_pmi(env);
    }
    pmu_set_limits(env);
}

/*
 * The event a general-purpose counter counts, as weights of instructions,
 * branches, and mispredicted branches; nothing for the events of
 * Intel SDM 325462-093 Vol. 3B, Table 22-3, that CPUID 0AH leaves out,
 * reference cycles and the last-level cache ones, and for any other event.
 */
static void pmu_event(CPUX86State *env, uint64_t sel, X86PMUCounter *ctr)
{
    unsigned cmask = extract64(sel, 24, 8);

    ctr->insns = ctr->branches = ctr->mispredicts = 0;
    if (IS_INTEL_CPU(env)) {
        switch (extract64(sel, 0, 16)) {
        case 0x003c: /* UnHalted Core Cycles */
        case 0x00c0: /* Instruction Retired */
            ctr->insns = 1;
            break;
        case 0x00c4: /* Branch Instruction Retired */
            ctr->branches = 1;
            break;
        case 0x00c5: /* Branch Misses Retired */
            ctr->mispredicts = 1;
            break;
        }
    } else {
        /*
         * The events of PPR for AMD Family 17h Model 20h, 55772 rev. 3.08,
         * 2.1.14.3.2 and 2.1.14.3.5, whatever the unit mask.
         */
        switch (extract64(sel, 0, 8) | extract64(sel, 32, 4) << 8) {
        case 0x076: /* Cycles not in Halt */
        case 0x0c0: /* Retired Instructions */
            ctr->insns = 1;
            break;
        case 0x0c2: /* Retired Branch Instructions */
            ctr->branches = 1;
            break;
        case 0x0c3: /* Retired Branch Instructions Mispredicted */
            ctr->mispredicts = 1;
            break;
        }
    }

    /*
     * With a counter mask, cycles with at least that many events count, or
     * with fewer if INV: at one instruction a cycle, a cycle has one of
     * the event or none.
     */
    if (cmask && (sel & EVTSEL_INV)) {
        if (cmask >= 2) {
            ctr->insns = 1;
            ctr->branches = ctr->mispredicts = 0;
        } else {
            ctr->insns = 1 - ctr->insns;
            ctr->branches = -ctr->branches;
            ctr->mispredicts = -ctr->mispredicts;
        }
    } else if (cmask >= 2) {
        ctr->insns = ctr->branches = ctr->mispredicts = 0;
    }
}

/* What each counter counts and in which buckets, after an update. */
static void pmu_configure(CPUX86State *env)
{
    X86PMUState *p = &env->pmu;
    bool intel = IS_INTEL_CPU(env);
    bool svme = (env->hflags & HF_GUEST_MASK) || (env->efer & MSR_EFER_SVME);

    p->active = false;
    for (unsigned c = 0; c < pmu_counters(env); c++) {
        X86PMUCounter *ctr = &p->ctr[c];
        uint8_t buckets = 0;

        if (c >= X86_PMU_GP_COUNTERS) {
            unsigned ctrl = extract64(env->msr_fixed_ctr_ctrl,
                                      4 * (c - X86_PMU_GP_COUNTERS), 4);

            /*
             * Instructions retired, core cycles, and reference cycles
             * (Intel SDM 325462-093 Vol. 3B, Table 22-1).
             */
            ctr->insns = 1;
            ctr->branches = ctr->mispredicts = 0;
            if (env->msr_global_ctrl & pmu_global_bit(c)) {
                buckets = (ctrl & 1 ? BUCKETS_OS : 0) |
                          (ctrl & 2 ? BUCKETS_USR : 0);
            }
            ctr->pmi = ctrl & 8;
        } else {
            uint64_t sel = env->msr_gp_evtsel[c];

            pmu_event(env, sel, ctr);
            if ((sel & EVTSEL_EN) &&
                (!intel || (env->msr_global_ctrl & pmu_global_bit(c)))) {
                buckets = (sel & EVTSEL_OS ? BUCKETS_OS : 0) |
                          (sel & EVTSEL_USR ? BUCKETS_USR : 0);
            }

            /*
             * Host/Guest Only: either selects guest or host mode, both
             * either, only with EFER.SVME (AMD64 Architecture Programmer's
             * Manual Volume 2, 24593 rev. 3.45, Table 13-4).
             */
            if (!intel && (sel & (AMD_EVTSEL_GUEST_ONLY |
                                  AMD_EVTSEL_HOST_ONLY))) {
                uint8_t modes = 0;

                if (sel & AMD_EVTSEL_GUEST_ONLY) {
                    modes |= BUCKETS_GUEST;
                }
                if ((sel & AMD_EVTSEL_HOST_ONLY) && svme) {
                    modes |= BUCKETS_HOST;
                }
                buckets &= modes;
            }
            ctr->pmi = sel & EVTSEL_INT;
        }
        if (!ctr->insns && !ctr->branches && !ctr->mispredicts) {
            buckets = 0;
        }
        ctr->buckets = buckets;
        ctr->events = pmu_events(env, ctr);
        p->active |= buckets != 0;
    }
    pmu_set_limits(env);
}

void x86_pmu_reconfigure(CPUX86State *env)
{
    pmu_update(env);
    pmu_configure(env);
}

/* A TB starts in a bucket past its limit. */
void HELPER(pmu_check)(CPUX86State *env)
{
    pmu_update(env);
}

/* Full-width writes through IA32_A_PMCx (Intel SDM 325462-093 22.2.8). */
static bool pmu_full_width(CPUX86State *env)
{
    return (env->features[FEAT_1_ECX] & CPUID_EXT_PDCM) &&
           (env->features[FEAT_PERF_CAPABILITIES] & PERF_CAP_FW_WRITE);
}

/*
 * The counter that MSR is, or -1, and whether it is the event select of
 * that counter rather than the counter itself.
 */
static int pmu_msr_counter(CPUX86State *env, uint32_t msr, bool *sel)
{
    *sel = false;
    if (IS_INTEL_CPU(env)) {
        if (msr - MSR_P6_PERFCTR0 < X86_PMU_GP_COUNTERS) {
            return msr - MSR_P6_PERFCTR0;
        }
        if (msr - MSR_IA32_PMC0 < X86_PMU_GP_COUNTERS) {
            return msr - MSR_IA32_PMC0;
        }
        if (msr - MSR_CORE_PERF_FIXED_CTR0 < MAX_FIXED_COUNTERS) {
            return X86_PMU_GP_COUNTERS + msr - MSR_CORE_PERF_FIXED_CTR0;
        }
        if (msr - MSR_P6_EVNTSEL0 < X86_PMU_GP_COUNTERS) {
            *sel = true;
            return msr - MSR_P6_EVNTSEL0;
        }
        return -1;
    }

    /*
     * AMD's legacy MSRs are the first 4 core counters' (AMD64 Architecture
     * Programmer's Manual Volume 2, 24593 rev. 3.45, 13.2.1).
     */
    if (msr - MSR_K7_PERFCTR0 < AMD_LEGACY_COUNTERS) {
        return msr - MSR_K7_PERFCTR0;
    }
    if (msr - MSR_K7_EVNTSEL0 < AMD_LEGACY_COUNTERS) {
        *sel = true;
        return msr - MSR_K7_EVNTSEL0;
    }
    if (msr - MSR_F15H_PERF_CTL0 < 2 * AMD_CORE_COUNTERS &&
        pmu_counters(env) == AMD_CORE_COUNTERS) {
        *sel = !((msr - MSR_F15H_PERF_CTL0) & 1);
        return (msr - MSR_F15H_PERF_CTL0) / 2;
    }
    return -1;
}

/*
 * RDMSR of the PMU's MSRs: 1 with *VAL, 0 for #GP, or -1 where MSR is
 * not one of them.
 */
int x86_pmu_rdmsr(CPUX86State *env, uint32_t msr, uint64_t *val)
{
    bool sel;
    int c;

    if (!x86_pmu_enabled(env)) {
        return -1;
    }
    c = pmu_msr_counter(env, msr, &sel);
    if (c >= 0) {
        if (msr - MSR_IA32_PMC0 < X86_PMU_GP_COUNTERS && IS_INTEL_CPU(env) &&
            !pmu_full_width(env)) {
            return 0;
        }
        if (sel) {
            *val = env->msr_gp_evtsel[c];
        } else {
            pmu_update(env);
            *val = *pmu_value(env, c);
        }
        return 1;
    }
    if (!IS_INTEL_CPU(env)) {
        return -1;
    }

    switch (msr) {
    case MSR_CORE_PERF_FIXED_CTR_CTRL:
        *val = env->msr_fixed_ctr_ctrl;
        return 1;
    case MSR_CORE_PERF_GLOBAL_STATUS:
        pmu_update(env);
        *val = env->msr_global_status;
        return 1;
    case MSR_CORE_PERF_GLOBAL_CTRL:
        *val = env->msr_global_ctrl;
        return 1;
    case MSR_CORE_PERF_GLOBAL_OVF_CTRL:
        *val = 0;
        return 1;
    case MSR_IA32_PERF_CAPABILITIES:
        if (!(env->features[FEAT_1_ECX] & CPUID_EXT_PDCM)) {
            return 0;
        }
        *val = env->features[FEAT_PERF_CAPABILITIES];
        return 1;
    default:
        return -1;
    }
}

/* A write of counter C, after its checks. */
static void pmu_write_counter(CPUX86State *env, unsigned c, uint64_t val)
{
    pmu_update(env);
    *pmu_value(env, c) = val & PMU_MASK;
    pmu_set_limits(env);
}

/*
 * WRMSR of the PMU's MSRs: 1 for success, 0 for #GP, or -1 where MSR is
 * not one of them.  IA32_PMCx's writes sign-extend their bit 31, IA32_A_PMCx
 * ones take the counter's width (Intel SDM 325462-093 Vol. 3B, 22.2.1 and
 * 22.2.8); AMD's take the counter's width too, and their reserved event
 * select bits are read-only zeros.
 */
int x86_pmu_wrmsr(CPUX86State *env, uint32_t msr, uint64_t val)
{
    bool intel = IS_INTEL_CPU(env);
    bool sel;
    int c;

    if (!x86_pmu_enabled(env)) {
        return -1;
    }
    c = pmu_msr_counter(env, msr, &sel);
    if (c >= 0) {
        if (sel) {
            if (intel && (val & INTEL_EVTSEL_RESERVED)) {
                return 0;
            }
            pmu_update(env);
            env->msr_gp_evtsel[c] = intel ? val : val & AMD_EVTSEL_DEFINED;
            pmu_configure(env);
        } else if (!intel) {
            pmu_write_counter(env, c, val);
        } else if (msr - MSR_P6_PERFCTR0 < X86_PMU_GP_COUNTERS) {
            pmu_write_counter(env, c, (int64_t)(int32_t)val);
        } else if ((msr - MSR_IA32_PMC0 < X86_PMU_GP_COUNTERS &&
                    !pmu_full_width(env)) || (val & ~PMU_MASK)) {
            return 0;
        } else {
            pmu_write_counter(env, c, val);
        }
        return 1;
    }
    if (!intel) {
        return -1;
    }

    switch (msr) {
    case MSR_CORE_PERF_FIXED_CTR_CTRL:
        if (val & ~FIXED_CTRL_DEFINED) {
            return 0;
        }
        pmu_update(env);
        env->msr_fixed_ctr_ctrl = val;
        pmu_configure(env);
        return 1;
    case MSR_CORE_PERF_GLOBAL_CTRL:
        if (val & ~GLOBAL_COUNTERS) {
            return 0;
        }
        x86_pmu_set_global_ctrl(env, val);
        return 1;
    case MSR_CORE_PERF_GLOBAL_OVF_CTRL:
        if (val & ~(GLOBAL_COUNTERS | GLOBAL_STATUS_OTHERS)) {
            return 0;
        }
        pmu_update(env);
        env->msr_global_status &= ~val;
        return 1;
    case MSR_CORE_PERF_GLOBAL_STATUS:
    case MSR_IA32_PERF_CAPABILITIES:
        return 0;
    default:
        return -1;
    }
}

bool x86_pmu_global_ctrl_valid(uint64_t val)
{
    return !(val & ~GLOBAL_COUNTERS);
}

void x86_pmu_set_global_ctrl(CPUX86State *env, uint64_t val)
{
    pmu_update(env);
    env->msr_global_ctrl = val & GLOBAL_COUNTERS;
    pmu_configure(env);
}

/*
 * RDPMC after its privilege checks and intercepts: false for #GP.  On
 * Intel, ECX[31:16] selects the counters, 0 general-purpose ones and 4000H
 * fixed ones, and ECX[15:0] the counter (Intel SDM 325462-093 Vol. 2B,
 * RDPMC); on AMD, ECX is the counter.
 */
bool x86_pmu_rdpmc(CPUX86State *env)
{
    uint32_t ecx = env->regs[R_ECX];
    unsigned c;
    uint64_t val;

    if (!x86_pmu_enabled(env)) {
        return false;
    }
    if (IS_INTEL_CPU(env)) {
        unsigned index = ecx & 0xffff;

        if ((ecx >> 16) == 0 && index < X86_PMU_GP_COUNTERS) {
            c = index;
        } else if ((ecx >> 16) == 0x4000 && index < MAX_FIXED_COUNTERS) {
            c = X86_PMU_GP_COUNTERS + index;
        } else {
            return false;
        }
    } else if (ecx < pmu_counters(env)) {
        c = ecx;
    } else {
        return false;
    }

    env->pmu.unretired = 1;
    pmu_update(env);
    env->pmu.unretired = 0;
    val = *pmu_value(env, c);
    env->regs[R_EAX] = (uint32_t)val;
    env->regs[R_EDX] = val >> 32;
    return true;
}

/*
 * A state restore at the instruction that WORD, its third insn_start word,
 * describes: the instructions from it to the end of TB did not retire.  The
 * next TB start takes them back, before another restore can come.
 */
void x86_pmu_restore(CPUX86State *env, const TranslationBlock *tb,
                     uint64_t word)
{
    X86PMUState *p = &env->pmu;

    if (!p->active) {
        return;
    }
    p->fix_pending = true;
    p->fix_bucket = x86_pmu_bucket(tb->flags);
    p->fix_insns = tb->icount - (word >> X86_PMU_INSN_INDEX_SHIFT);
    p->fix_branches = !!(word & X86_PMU_INSN_BRANCH);
    p->fix_mispredicts = !!(word & X86_PMU_INSN_MISPREDICT);
    memset(p->limit, 0, sizeof(p->limit));
}

/*
 * The instruction at which the state was restored retires after all, for
 * the PMU and for SVM's PAUSE filter (x86_restore_state_to_opc).
 */
void x86_pmu_restored_retired(CPUX86State *env)
{
    if (env->pmu.fix_pending) {
        env->pmu.fix_insns--;
    }
    if (env->hflags & HF_PAUSE_COUNT_MASK) {
        env->svm_pause_cycles++;
    }
}

/*
 * INT n, INT3, or INTO, branches, raises its software interrupt, and
 * retires only once the interrupt is delivered.
 */
void x86_pmu_soft_int(CPUX86State *env)
{
    if (x86_pmu_enabled(env) && env->pmu.active) {
        pmu_take_back(env);
        env->pmu.soft_int = 1 + x86_pmu_bucket(env->hflags);
    }
}

/*
 * An event's delivery starts: not that of the software interrupt raised,
 * whose own delivery failed then.  On AMD, exceptions and interrupts count
 * as branches and as mispredicted ones.
 */
void x86_pmu_event_start(CPUX86State *env, int is_int)
{
    X86PMUState *p = &env->pmu;

    if (is_int) {
        return;
    }
    if (p->soft_int) {
        pmu_take_back(env);
    }
    if (x86_pmu_enabled(env) && p->active && !IS_INTEL_CPU(env)) {
        unsigned b = x86_pmu_bucket(env->hflags);

        p->branches[b]++;
        p->mispredicts[b]++;
    }
}

void x86_pmu_event_end(CPUX86State *env)
{
    env->pmu.soft_int = 0;
}
