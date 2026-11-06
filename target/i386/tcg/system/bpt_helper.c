/*
 *  i386 breakpoint helpers - system code
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
#include "exec/helper-proto.h"
#include "exec/watchpoint.h"
#include "tcg/helper-tcg.h"


static inline bool hw_local_breakpoint_enabled(unsigned long dr7, int index)
{
    return (dr7 >> (index * 2)) & 1;
}

static inline bool hw_global_breakpoint_enabled(unsigned long dr7, int index)
{
    return (dr7 >> (index * 2)) & 2;

}
static inline bool hw_breakpoint_enabled(unsigned long dr7, int index)
{
    return hw_global_breakpoint_enabled(dr7, index) ||
           hw_local_breakpoint_enabled(dr7, index);
}

static inline int hw_breakpoint_type(unsigned long dr7, int index)
{
    return (dr7 >> (DR7_TYPE_SHIFT + (index * 4))) & 3;
}

static inline int hw_breakpoint_len(unsigned long dr7, int index)
{
    int len = ((dr7 >> (DR7_LEN_SHIFT + (index * 4))) & 3);
    return (len == 2) ? 8 : len + 1;
}

/*
 * AMD's DR0-3_ADDR_MASK come with DataBkptExt, whose bits set exclude
 * address bits from breakpoint matches: bits 11:0 for instruction
 * breakpoints, all of DR0's for data ones; AddrMaskExt extends them to
 * all bits and registers (AMD64 Architecture Programmer's Manual Volume
 * 2, 24593 rev. 3.45, 13.1.7).
 */
bool x86_dr_addr_mask_exists(CPUX86State *env, int index)
{
    return env->features[FEAT_8000_0001_ECX] &
           (CPUID_EXT3_BPEXT | CPUID_EXT3_ADDRMASKEXT);
}

/* The address bits a data breakpoint leaves out of its match. */
static uint64_t hw_breakpoint_ignored(CPUX86State *env, int index)
{
    uint32_t ecx = env->features[FEAT_8000_0001_ECX];
    uint64_t ignored = hw_breakpoint_len(env->dr[7], index) - 1;

    if ((ecx & CPUID_EXT3_ADDRMASKEXT) ||
        (index == 0 && (ecx & CPUID_EXT3_BPEXT))) {
        ignored |= env->dr_addr_mask[index];
    }
    return ignored;
}

/* The address bits an instruction breakpoint leaves out of its match. */
static uint64_t hw_breakpoint_insn_ignored(CPUX86State *env, int index)
{
    uint32_t ecx = env->features[FEAT_8000_0001_ECX];

    if (ecx & CPUID_EXT3_ADDRMASKEXT) {
        return env->dr_addr_mask[index];
    }
    return ecx & CPUID_EXT3_BPEXT ? env->dr_addr_mask[index] & 0xfff : 0;
}

/*
 * Instruction breakpoints match the linear address of an instruction's
 * first byte (Intel SDM 325462-093 Vol. 3B, 20.2.1 and 20.2.4).
 */
static target_ulong insn_linear(CPUX86State *env)
{
    return env->segs[R_CS].base + env->eip;
}

/*
 * Upper Address Ignore, while active, leaves bits 63:57 of DR0-3 out of
 * data breakpoints' matches (AMD64 Architecture Programmer's Manual Volume
 * 2, 24593 rev. 3.46, 5.10.4).
 */
static bool hw_breakpoint_uai(CPUX86State *env)
{
    return (env->efer & MSR_EFER_UAIE) && (env->hflags & HF_CS64_MASK);
}

static int hw_watchpoint_insert(CPUX86State *env, int index, int flags)
{
    uint64_t ignored = hw_breakpoint_ignored(env, index);
    vaddr addr = env->dr[index] & ~ignored;
    vaddr last = env->dr[index] | ignored;

    /*
     * Where Upper Address Ignore may take bits 63:57 out of the match, the
     * accesses that match have them as copies of bit 56.
     */
    if (env->features[FEAT_8000_0021_EAX] & CPUID_8000_0021_EAX_UAI) {
        addr = sextract64(addr, 0, 57);
        last = sextract64(last, 0, 57);
    }
    /*
     * One range from the lowest address that matches to the highest;
     * x86_debug_check_watchpoint() drops what a mask with holes leaves.
     */
    return cpu_watchpoint_insert(env_cpu(env), addr, last - addr + 1,
                                 flags, &env->cpu_watchpoint[index]);
}

bool x86_debug_check_watchpoint(CPUState *cs, CPUWatchpoint *wp)
{
    CPUX86State *env = cpu_env(cs);
    int i;

    for (i = 0; i < DR7_MAX_BP; i++) {
        if (env->cpu_watchpoint[i] == wp) {
            uint64_t ignored = hw_breakpoint_ignored(env, i);

            if (hw_breakpoint_uai(env)) {
                ignored |= MAKE_64BIT_MASK(57, 7);
            }
            return !((wp->hitaddr ^ env->dr[i]) & ~ignored);
        }
    }
    return true;
}

static int hw_breakpoint_insert(CPUX86State *env, int index)
{
    CPUState *cs = env_cpu(env);
    target_ulong dr7 = env->dr[7];
    target_ulong drN = env->dr[index];
    int err = 0;

    switch (hw_breakpoint_type(dr7, index)) {
    case DR7_TYPE_BP_INST:
        if (hw_breakpoint_enabled(dr7, index)) {
            err = cpu_breakpoint_insert(cs, drN, BP_CPU,
                                        &env->cpu_breakpoint[index]);
            if (!err) {
                env->cpu_breakpoint[index]->mask =
                    hw_breakpoint_insn_ignored(env, index);
            }
        }
        break;

    case DR7_TYPE_IO_RW:
        /* Notice when bpt_io has breakpoints to look at.  */
        return hw_breakpoint_enabled(env->dr[7], index)
               ? HF2_IOBPT_MASK : 0;

    case DR7_TYPE_DATA_WR:
        if (hw_breakpoint_enabled(dr7, index)) {
            err = hw_watchpoint_insert(env, index, BP_CPU | BP_MEM_WRITE);
        }
        break;

    case DR7_TYPE_DATA_RW:
        if (hw_breakpoint_enabled(dr7, index)) {
            err = hw_watchpoint_insert(env, index, BP_CPU | BP_MEM_ACCESS);
        }
        break;
    }
    if (err) {
        env->cpu_breakpoint[index] = NULL;
    }
    return 0;
}

static void hw_breakpoint_remove(CPUX86State *env, int index)
{
    CPUState *cs = env_cpu(env);

    switch (hw_breakpoint_type(env->dr[7], index)) {
    case DR7_TYPE_BP_INST:
        if (env->cpu_breakpoint[index]) {
            cpu_breakpoint_remove_by_ref(cs, env->cpu_breakpoint[index]);
            env->cpu_breakpoint[index] = NULL;
        }
        break;

    case DR7_TYPE_DATA_WR:
    case DR7_TYPE_DATA_RW:
        if (env->cpu_watchpoint[index]) {
            cpu_watchpoint_remove_by_ref(cs, env->cpu_watchpoint[index]);
            env->cpu_watchpoint[index] = NULL;
        }
        break;

    case DR7_TYPE_IO_RW:
        /* HF2_IOBPT_MASK cleared elsewhere.  */
        break;
    }
}

void x86_set_dr_addr_mask(CPUX86State *env, int index, uint64_t mask)
{
    if (hw_breakpoint_enabled(env->dr[7], index) &&
        hw_breakpoint_type(env->dr[7], index) != DR7_TYPE_IO_RW) {
        hw_breakpoint_remove(env, index);
        env->dr_addr_mask[index] = mask;
        hw_breakpoint_insert(env, index);
    } else {
        env->dr_addr_mask[index] = mask;
    }
}

void cpu_x86_update_dr7(CPUX86State *env, uint32_t new_dr7)
{
    target_ulong old_dr7 = env->dr[7];
    int iobpt = 0;
    int i;

    new_dr7 |= DR7_FIXED_1;

    /* If nothing is changing except the global/local enable bits,
       then we can make the change more efficient.  */
    if (((old_dr7 ^ new_dr7) & ~0xff) == 0) {
        /* Fold the global and local enable bits together into the
           global fields, then xor to show which registers have
           changed collective enable state.  */
        int mod = ((old_dr7 | old_dr7 * 2) ^ (new_dr7 | new_dr7 * 2)) & 0xff;

        for (i = 0; i < DR7_MAX_BP; i++) {
            if ((mod & (2 << i * 2)) && !hw_breakpoint_enabled(new_dr7, i)) {
                hw_breakpoint_remove(env, i);
            }
        }
        env->dr[7] = new_dr7;
        for (i = 0; i < DR7_MAX_BP; i++) {
            if (mod & (2 << i * 2) && hw_breakpoint_enabled(new_dr7, i)) {
                iobpt |= hw_breakpoint_insert(env, i);
            } else if (hw_breakpoint_type(new_dr7, i) == DR7_TYPE_IO_RW
                       && hw_breakpoint_enabled(new_dr7, i)) {
                iobpt |= HF2_IOBPT_MASK;
            }
        }
    } else {
        for (i = 0; i < DR7_MAX_BP; i++) {
            hw_breakpoint_remove(env, i);
        }
        env->dr[7] = new_dr7;
        for (i = 0; i < DR7_MAX_BP; i++) {
            iobpt |= hw_breakpoint_insert(env, i);
        }
    }

    env->hflags2 = (env->hflags2 & ~HF2_IOBPT_MASK) | iobpt;
}

/*
 * The B0-B3 bits of the breakpoints that hit, instruction ones at EIP only
 * with insn, and whether an enabled one did; raising the #DB writes them
 * to DR6.
 */
static uint32_t breakpoint_hits(CPUX86State *env, bool insn, bool *enabled)
{
    uint32_t hits = 0;
    int reg;
    bool hit_enabled = false;

    for (reg = 0; reg < DR7_MAX_BP; reg++) {
        bool bp_match = false;
        bool wp_match = false;

        switch (hw_breakpoint_type(env->dr[7], reg)) {
        case DR7_TYPE_BP_INST:
            if (insn && !((env->dr[reg] ^ insn_linear(env)) &
                          ~hw_breakpoint_insn_ignored(env, reg))) {
                bp_match = true;
            }
            break;
        case DR7_TYPE_DATA_WR:
        case DR7_TYPE_DATA_RW:
            if (env->cpu_watchpoint[reg] &&
                env->cpu_watchpoint[reg]->flags & BP_WATCHPOINT_HIT) {
                wp_match = true;
            }
            break;
        case DR7_TYPE_IO_RW:
            break;
        }
        if (bp_match || wp_match) {
            hits |= 1 << reg;
            if (hw_breakpoint_enabled(env->dr[7], reg)) {
                hit_enabled = true;
            }
        }
    }

    if (enabled) {
        *enabled = hit_enabled;
    }
    return hits;
}

uint32_t hw_breakpoint_hits(CPUX86State *env, bool *enabled)
{
    return breakpoint_hits(env, true, enabled);
}

/* The data breakpoints the last instruction matched. */
uint32_t hw_data_breakpoint_hits(CPUX86State *env, bool *enabled)
{
    return breakpoint_hits(env, false, enabled);
}

void breakpoint_handler(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    if (cs->watchpoint_hit) {
        if (cs->watchpoint_hit->flags & BP_CPU) {
            bool enabled;
            uint32_t hits;

            cs->watchpoint_hit = NULL;
            hits = hw_breakpoint_hits(env, &enabled);
            if (!enabled) {
                cpu_loop_exit_noexc(cs);
            }
            /*
             * MOV SS and POP SS hold the #DB of their data breakpoints
             * until the instruction boundary after the next instruction
             * (Intel SDM 325462-093 Vol. 3A, 7.8.3), where a #DB of that
             * instruction, ICEBP's or TF's, takes their bits too.
             */
            if ((env->hflags & HF_INHIBIT_IRQ_MASK) && env->shadow_movss) {
                env->db_movss |= hits;
                cpu_loop_exit_noexc(cs);
            }
            raise_debug_exception(env, hits, 0);
        }
    } else {
        if (cpu_breakpoint_test(cs, insn_linear(env), BP_CPU)) {
            raise_debug_exception(env, hw_breakpoint_hits(env, NULL), 0);
        }
    }
}

target_ulong HELPER(get_dr)(CPUX86State *env, int reg)
{
    int dr = reg;

    if (reg >= 4 && reg < 6) {
        if (env->cr[4] & CR4_DE_MASK) {
            raise_exception_ra(env, EXCP06_ILLOP, GETPC());
        } else {
            reg += 2;
        }
    }

    if (env->dr[7] & DR7_GD) {
        raise_debug_exception(env, DR6_BD, GETPC());
    }
    x86_svm_late_intercept(env, SVM_EXIT_READ_DR0 + dr, GETPC());

    return env->dr[reg];
}

void HELPER(set_dr)(CPUX86State *env, int reg, target_ulong t0)
{
    int dr = reg;

    if (reg >= 4 && reg < 6) {
        if (env->cr[4] & CR4_DE_MASK) {
            raise_exception_ra(env, EXCP06_ILLOP, GETPC());
        } else {
            reg += 2;
        }
    }

    if (env->dr[7] & DR7_GD) {
        raise_debug_exception(env, DR6_BD, GETPC());
    }
    if (reg >= 6 && (t0 & DR_RESERVED_MASK)) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }
    x86_svm_late_intercept(env, SVM_EXIT_WRITE_DR0 + dr, GETPC());

    if (reg < 4) {
        if (hw_breakpoint_enabled(env->dr[7], reg)
            && hw_breakpoint_type(env->dr[7], reg) != DR7_TYPE_IO_RW) {
            hw_breakpoint_remove(env, reg);
            env->dr[reg] = t0;
            hw_breakpoint_insert(env, reg);
        } else {
            env->dr[reg] = t0;
        }
    } else if (reg == 6) {
        /*
         * With OS bus-lock detection, BLD is software's to set again after
         * a bus lock's #DB cleared it (Intel SDM 325462-093 Vol. 3B,
         * 20.2.3).
         */
        env->dr[6] = t0 | DR6_FIXED_1;
        if (env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_BUS_LOCK_DETECT) {
            env->dr[6] &= t0 | ~(target_ulong)DR6_BLD;
        }
    } else {
        cpu_x86_update_dr7(env, t0);
    }
}

/* Check if Port I/O is trapped by a breakpoint.  */
void HELPER(bpt_io)(CPUX86State *env, uint32_t port,
                   uint32_t size, target_ulong next_eip)
{
    target_ulong dr7 = env->dr[7];
    int i, hit = 0;

    if (!(env->hflags2 & HF2_IOBPT_MASK)) {
        return;
    }
    for (i = 0; i < DR7_MAX_BP; ++i) {
        if (hw_breakpoint_type(dr7, i) == DR7_TYPE_IO_RW
            && hw_breakpoint_enabled(dr7, i)) {
            int bpt_len = hw_breakpoint_len(dr7, i);
            if (port + size - 1 >= env->dr[i]
                && port <= env->dr[i] + bpt_len - 1) {
                hit |= 1 << i;
            }
        }
    }

    if (hit) {
        env->eip = next_eip;
        if (x86_vmx_mtf(env)) {
            do_end_instruction(env);
            x86_vmx_mtf_step(env, hit | x86_step_trap(env, false));
        }
        raise_debug_exception(env, hit, 0);
    }
}

/* The #DB MOV SS or POP SS held, at the instruction boundary it waited for. */
void HELPER(db_pending)(CPUX86State *env)
{
    raise_debug_exception(env, 0, GETPC());
}
