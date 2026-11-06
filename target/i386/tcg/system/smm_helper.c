/*
 *  x86 SMM helpers (system-only)
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
#include "exec/log.h"
#include "exec/cputlb.h"
#include "accel/tcg/cpu-loop.h"
#include "system/runstate.h"
#include "tcg/helper-tcg.h"

/*
 * The SMM revision identifiers of the 64-bit and 32-bit state-save area
 * formats, with SMBASE relocation (bit 17).
 */
#define SMM_REVISION_64 0x00020064
#define SMM_REVISION_32 0x00020000

static void sm_state_init_64(X86CPU *cpu)
{
#ifdef TARGET_X86_64
    CPUX86State *env = &cpu->env;
    CPUState *cs = CPU(cpu);
    SegmentCache *dt;
    int i, offset;
    target_ulong sm_state = env->smbase + 0x8000;

    for (i = 0; i < 6; i++) {
        dt = &env->segs[i];
        offset = 0x7e00 + i * 16;
        x86_stw_phys(cs, sm_state + offset, dt->selector);
        x86_stw_phys(cs, sm_state + offset + 2, (dt->flags >> 8) & 0xf0ff);
        x86_stl_phys(cs, sm_state + offset + 4, dt->limit);
        x86_stq_phys(cs, sm_state + offset + 8, dt->base);
    }

    x86_stq_phys(cs, sm_state + 0x7e68, env->gdt.base);
    x86_stw_phys(cs, sm_state + 0x7e64, env->gdt.limit);

    x86_stw_phys(cs, sm_state + 0x7e70, env->ldt.selector);
    x86_stq_phys(cs, sm_state + 0x7e78, env->ldt.base);
    x86_stl_phys(cs, sm_state + 0x7e74, env->ldt.limit);
    x86_stw_phys(cs, sm_state + 0x7e72, (env->ldt.flags >> 8) & 0xf0ff);

    x86_stq_phys(cs, sm_state + 0x7e88, env->idt.base);
    x86_stw_phys(cs, sm_state + 0x7e84, env->idt.limit);

    x86_stw_phys(cs, sm_state + 0x7e90, env->tr.selector);
    x86_stq_phys(cs, sm_state + 0x7e98, env->tr.base);
    x86_stl_phys(cs, sm_state + 0x7e94, env->tr.limit);
    x86_stw_phys(cs, sm_state + 0x7e92, (env->tr.flags >> 8) & 0xf0ff);

    /* ??? Vol 1, 16.5.6 Intel MPX and SMM says that IA32_BNDCFGS
       is saved at offset 7ED0.  Vol 3, 34.4.1.1, Table 32-2, has
       7EA0-7ED7 as "reserved".  What's this, and what's really
       supposed to happen?  */
    x86_stq_phys(cs, sm_state + 0x7ed0, env->efer);

    x86_stq_phys(cs, sm_state + 0x7ff8, env->regs[R_EAX]);
    x86_stq_phys(cs, sm_state + 0x7ff0, env->regs[R_ECX]);
    x86_stq_phys(cs, sm_state + 0x7fe8, env->regs[R_EDX]);
    x86_stq_phys(cs, sm_state + 0x7fe0, env->regs[R_EBX]);
    x86_stq_phys(cs, sm_state + 0x7fd8, env->regs[R_ESP]);
    x86_stq_phys(cs, sm_state + 0x7fd0, env->regs[R_EBP]);
    x86_stq_phys(cs, sm_state + 0x7fc8, env->regs[R_ESI]);
    x86_stq_phys(cs, sm_state + 0x7fc0, env->regs[R_EDI]);
    for (i = 8; i < 16; i++) {
        x86_stq_phys(cs, sm_state + 0x7ff8 - i * 8, env->regs[i]);
    }
    /*
     * RFLAGS, the debug registers, and the control registers take
     * quadwords, CR4's upper half holding CR4.FRED, and GDTR's and IDTR's
     * limits words (AMD64 Architecture Programmer's Manual Volume 2, 24593
     * rev. 3.46, Table 10-1).
     */
    x86_stq_phys(cs, sm_state + 0x7f78, env->eip);
    x86_stq_phys(cs, sm_state + 0x7f70, cpu_compute_eflags(env));
    x86_stq_phys(cs, sm_state + 0x7f68, env->dr[6]);
    x86_stq_phys(cs, sm_state + 0x7f60, env->dr[7]);
    x86_stq_phys(cs, sm_state + 0x7f48, env->cr[4]);
    x86_stq_phys(cs, sm_state + 0x7f50, env->cr[3]);
    x86_stq_phys(cs, sm_state + 0x7f58, env->cr[0]);

    x86_stl_phys(cs, sm_state + 0x7efc, SMM_REVISION_64);
    x86_stl_phys(cs, sm_state + 0x7f00, env->smbase);
#else
    g_assert_not_reached();
#endif
}

static void sm_state_init_32(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;
    CPUState *cs = CPU(cpu);
    SegmentCache *dt;
    int i, offset;
    target_ulong sm_state = env->smbase + 0x8000;

    x86_stl_phys(cs, sm_state + 0x7ffc, env->cr[0]);
    x86_stl_phys(cs, sm_state + 0x7ff8, env->cr[3]);
    x86_stl_phys(cs, sm_state + 0x7ff4, cpu_compute_eflags(env));
    x86_stl_phys(cs, sm_state + 0x7ff0, env->eip);
    x86_stl_phys(cs, sm_state + 0x7fec, env->regs[R_EDI]);
    x86_stl_phys(cs, sm_state + 0x7fe8, env->regs[R_ESI]);
    x86_stl_phys(cs, sm_state + 0x7fe4, env->regs[R_EBP]);
    x86_stl_phys(cs, sm_state + 0x7fe0, env->regs[R_ESP]);
    x86_stl_phys(cs, sm_state + 0x7fdc, env->regs[R_EBX]);
    x86_stl_phys(cs, sm_state + 0x7fd8, env->regs[R_EDX]);
    x86_stl_phys(cs, sm_state + 0x7fd4, env->regs[R_ECX]);
    x86_stl_phys(cs, sm_state + 0x7fd0, env->regs[R_EAX]);
    x86_stl_phys(cs, sm_state + 0x7fcc, env->dr[6]);
    x86_stl_phys(cs, sm_state + 0x7fc8, env->dr[7]);

    x86_stl_phys(cs, sm_state + 0x7fc4, env->tr.selector);
    x86_stl_phys(cs, sm_state + 0x7f64, env->tr.base);
    x86_stl_phys(cs, sm_state + 0x7f60, env->tr.limit);
    x86_stl_phys(cs, sm_state + 0x7f5c, (env->tr.flags >> 8) & 0xf0ff);

    x86_stl_phys(cs, sm_state + 0x7fc0, env->ldt.selector);
    x86_stl_phys(cs, sm_state + 0x7f80, env->ldt.base);
    x86_stl_phys(cs, sm_state + 0x7f7c, env->ldt.limit);
    x86_stl_phys(cs, sm_state + 0x7f78, (env->ldt.flags >> 8) & 0xf0ff);

    x86_stl_phys(cs, sm_state + 0x7f74, env->gdt.base);
    x86_stl_phys(cs, sm_state + 0x7f70, env->gdt.limit);

    x86_stl_phys(cs, sm_state + 0x7f58, env->idt.base);
    x86_stl_phys(cs, sm_state + 0x7f54, env->idt.limit);

    for (i = 0; i < 6; i++) {
        dt = &env->segs[i];
        if (i < 3) {
            offset = 0x7f84 + i * 12;
        } else {
            offset = 0x7f2c + (i - 3) * 12;
        }
        x86_stl_phys(cs, sm_state + 0x7fa8 + i * 4, dt->selector);
        x86_stl_phys(cs, sm_state + offset + 8, dt->base);
        x86_stl_phys(cs, sm_state + offset + 4, dt->limit);
        x86_stl_phys(cs, sm_state + offset, (dt->flags >> 8) & 0xf0ff);
    }
    x86_stl_phys(cs, sm_state + 0x7f14, env->cr[4]);

    x86_stl_phys(cs, sm_state + 0x7efc, SMM_REVISION_32);
    x86_stl_phys(cs, sm_state + 0x7ef8, env->smbase);
}

void do_smm_enter(X86CPU *cpu)
{
    CPUX86State *env = &cpu->env;

    qemu_log_mask(CPU_LOG_INT, "SMM: enter\n");
    log_cpu_state_mask(CPU_LOG_INT, CPU(cpu), CPU_DUMP_CCOP);

    env->msr_smi_count++;
    env->hflags |= HF_SMM_MASK;
    x86_vmx_smm_enter(env);
    /*
     * TLB entries keep the memory attributes they were filled with, and
     * the MMU indexes do not tell SMM from normal operation.
     */
    tlb_flush(CPU(cpu));
    if (env->hflags2 & HF2_NMI_MASK) {
        env->hflags2 |= HF2_SMM_INSIDE_NMI_MASK;
    } else {
        env->hflags2 |= HF2_NMI_MASK;
    }

    if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM) {
        sm_state_init_64(cpu);
        env->smm_svme = env->efer & MSR_EFER_SVME;
        cpu_load_efer(env, 0);
    } else {
        sm_state_init_32(cpu);
    }

    /* init SMM cpu state */

    cpu_load_eflags(env, 0, ~(CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C |
                              DF_MASK));
    env->eip = 0x00008000;
    cpu_x86_update_cr0(env,
                       env->cr[0] & ~(CR0_PE_MASK | CR0_EM_MASK | CR0_TS_MASK |
                                      CR0_PG_MASK));
    cpu_x86_update_cr4(env, 0);
    cpu_x86_update_dr7(env, 0x00000400);

    cpu_x86_load_seg_cache(env, R_CS, (env->smbase >> 4) & 0xffff, env->smbase,
                           0xffffffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_G_MASK | DESC_A_MASK);
    cpu_x86_load_seg_cache(env, R_DS, 0, 0, 0xffffffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_G_MASK | DESC_A_MASK);
    cpu_x86_load_seg_cache(env, R_ES, 0, 0, 0xffffffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_G_MASK | DESC_A_MASK);
    cpu_x86_load_seg_cache(env, R_SS, 0, 0, 0xffffffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_G_MASK | DESC_A_MASK);
    cpu_x86_load_seg_cache(env, R_FS, 0, 0, 0xffffffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_G_MASK | DESC_A_MASK);
    cpu_x86_load_seg_cache(env, R_GS, 0, 0, 0xffffffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_G_MASK | DESC_A_MASK);
}

/*
 * What RSM restores where the state-save area does not say, AMD's processors
 * restoring some of it by default instead of shutting down (AMD64
 * Architecture Programmer's Manual Volume 2, 24593 rev. 3.46, 10.4, and
 * Volume 3, 24594 rev. 3.39, RSM): CPL 0 in real mode and 3 in virtual-8086
 * mode, RFLAGS.VM in protected mode outside long mode only, EFER.SVME as at
 * the SMI, canonical bases for FS, GS, and the system tables, and 32-bit bases
 * for CS, DS, ES, and SS. EFER.LMA follows EFER.LME, CR0.PG, and CR4.PAE on
 * any processor, as CR0's load sets it.
 */
#ifdef TARGET_X86_64
static uint64_t rsm_base(CPUX86State *env, int seg, uint64_t base)
{
    int shift = env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_LA57 ? 64 - 57
                                                                  : 64 - 48;

    if (IS_INTEL_CPU(env)) {
        return base;
    }
    if (seg == R_CS || seg == R_DS || seg == R_ES || seg == R_SS) {
        return (uint32_t)base;
    }
    return (int64_t)(base << shift) >> shift;
}
#endif

static uint32_t rsm_eflags(CPUX86State *env, uint32_t eflags, uint64_t cr0,
                           bool lma)
{
    if (!IS_INTEL_CPU(env) && (!(cr0 & CR0_PE_MASK) || lma)) {
        eflags &= ~VM_MASK;
    }
    return eflags;
}

static void rsm_cpl(CPUX86State *env, uint64_t cr0)
{
    if (!IS_INTEL_CPU(env) && !(cr0 & CR0_PE_MASK)) {
        env->hflags &= ~HF_CPL_MASK;
    } else if (!IS_INTEL_CPU(env) && (env->eflags & VM_MASK)) {
        env->hflags |= HF_CPL_MASK;
    }
}

static void rsm_load_regs_64(CPUX86State *env)
{
#ifdef TARGET_X86_64
    CPUState *cs = env_cpu(env);
    target_ulong sm_state;
    int i, offset;
    uint32_t val;
    uint64_t efer, cr0, cr4;
    bool lma;

    sm_state = env->smbase + 0x8000;
    efer = x86_ldq_phys(cs, sm_state + 0x7ed0) & ~MSR_EFER_LMA;
    cr0 = x86_ldq_phys(cs, sm_state + 0x7f58);
    cr4 = x86_ldq_phys(cs, sm_state + 0x7f48);
    lma = (efer & MSR_EFER_LME) && (cr0 & CR0_PG_MASK) &&
          (cr4 & CR4_PAE_MASK);
    if (!IS_INTEL_CPU(env)) {
        efer = (efer & ~MSR_EFER_SVME) | (env->smm_svme ? MSR_EFER_SVME : 0);
    }

    cpu_load_efer(env, efer);

    env->gdt.base = rsm_base(env, -1, x86_ldq_phys(cs, sm_state + 0x7e68));
    env->gdt.limit = x86_lduw_phys(cs, sm_state + 0x7e64);

    env->ldt.selector = x86_lduw_phys(cs, sm_state + 0x7e70);
    env->ldt.base = rsm_base(env, -1, x86_ldq_phys(cs, sm_state + 0x7e78));
    env->ldt.limit = x86_ldl_phys(cs, sm_state + 0x7e74);
    env->ldt.flags = (x86_lduw_phys(cs, sm_state + 0x7e72) & 0xf0ff) << 8;

    env->idt.base = rsm_base(env, -1, x86_ldq_phys(cs, sm_state + 0x7e88));
    env->idt.limit = x86_lduw_phys(cs, sm_state + 0x7e84);

    env->tr.selector = x86_lduw_phys(cs, sm_state + 0x7e90);
    env->tr.base = rsm_base(env, -1, x86_ldq_phys(cs, sm_state + 0x7e98));
    env->tr.limit = x86_ldl_phys(cs, sm_state + 0x7e94);
    env->tr.flags = (x86_lduw_phys(cs, sm_state + 0x7e92) & 0xf0ff) << 8;

    env->regs[R_EAX] = x86_ldq_phys(cs, sm_state + 0x7ff8);
    env->regs[R_ECX] = x86_ldq_phys(cs, sm_state + 0x7ff0);
    env->regs[R_EDX] = x86_ldq_phys(cs, sm_state + 0x7fe8);
    env->regs[R_EBX] = x86_ldq_phys(cs, sm_state + 0x7fe0);
    env->regs[R_ESP] = x86_ldq_phys(cs, sm_state + 0x7fd8);
    env->regs[R_EBP] = x86_ldq_phys(cs, sm_state + 0x7fd0);
    env->regs[R_ESI] = x86_ldq_phys(cs, sm_state + 0x7fc8);
    env->regs[R_EDI] = x86_ldq_phys(cs, sm_state + 0x7fc0);
    for (i = 8; i < 16; i++) {
        env->regs[i] = x86_ldq_phys(cs, sm_state + 0x7ff8 - i * 8);
    }
    env->eip = x86_ldq_phys(cs, sm_state + 0x7f78);
    cpu_load_eflags(env,
                    rsm_eflags(env, x86_ldl_phys(cs, sm_state + 0x7f70),
                               cr0, lma),
                    ~(CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C | DF_MASK));
    x86_load_dr6(env, x86_ldl_phys(cs, sm_state + 0x7f68));
    cpu_x86_update_dr7(env, x86_ldl_phys(cs, sm_state + 0x7f60));

    cpu_x86_update_cr4(env, cr4);
    cpu_x86_update_cr3(env, x86_ldq_phys(cs, sm_state + 0x7f50));
    cpu_x86_update_cr0(env, cr0);

    for (i = 0; i < 6; i++) {
        offset = 0x7e00 + i * 16;
        cpu_x86_load_seg_cache(env, i,
                               x86_lduw_phys(cs, sm_state + offset),
                               rsm_base(env, i,
                                        x86_ldq_phys(cs,
                                                     sm_state + offset + 8)),
                               x86_ldl_phys(cs, sm_state + offset + 4),
                               (x86_lduw_phys(cs, sm_state + offset + 2) &
                                0xf0ff) << 8);
    }
    rsm_cpl(env, cr0);

    val = x86_ldl_phys(cs, sm_state + 0x7efc); /* revision ID */
    if (val & 0x20000) {
        env->smbase = x86_ldl_phys(cs, sm_state + 0x7f00);
    }
#else
    g_assert_not_reached();
#endif
}

static void rsm_load_regs_32(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);
    target_ulong sm_state;
    int i, offset;
    uint32_t val, cr0;

    sm_state = env->smbase + 0x8000;
    cr0 = x86_ldl_phys(cs, sm_state + 0x7ffc);

    cpu_x86_update_cr0(env, cr0);
    cpu_x86_update_cr3(env, x86_ldl_phys(cs, sm_state + 0x7ff8));
    cpu_load_eflags(env,
                    rsm_eflags(env, x86_ldl_phys(cs, sm_state + 0x7ff4), cr0,
                               false),
                    ~(CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C | DF_MASK));
    env->eip = x86_ldl_phys(cs, sm_state + 0x7ff0);
    env->regs[R_EDI] = x86_ldl_phys(cs, sm_state + 0x7fec);
    env->regs[R_ESI] = x86_ldl_phys(cs, sm_state + 0x7fe8);
    env->regs[R_EBP] = x86_ldl_phys(cs, sm_state + 0x7fe4);
    env->regs[R_ESP] = x86_ldl_phys(cs, sm_state + 0x7fe0);
    env->regs[R_EBX] = x86_ldl_phys(cs, sm_state + 0x7fdc);
    env->regs[R_EDX] = x86_ldl_phys(cs, sm_state + 0x7fd8);
    env->regs[R_ECX] = x86_ldl_phys(cs, sm_state + 0x7fd4);
    env->regs[R_EAX] = x86_ldl_phys(cs, sm_state + 0x7fd0);
    x86_load_dr6(env, x86_ldl_phys(cs, sm_state + 0x7fcc));
    cpu_x86_update_dr7(env, x86_ldl_phys(cs, sm_state + 0x7fc8));

    env->tr.selector = x86_ldl_phys(cs, sm_state + 0x7fc4) & 0xffff;
    env->tr.base = x86_ldl_phys(cs, sm_state + 0x7f64);
    env->tr.limit = x86_ldl_phys(cs, sm_state + 0x7f60);
    env->tr.flags = (x86_ldl_phys(cs, sm_state + 0x7f5c) & 0xf0ff) << 8;

    env->ldt.selector = x86_ldl_phys(cs, sm_state + 0x7fc0) & 0xffff;
    env->ldt.base = x86_ldl_phys(cs, sm_state + 0x7f80);
    env->ldt.limit = x86_ldl_phys(cs, sm_state + 0x7f7c);
    env->ldt.flags = (x86_ldl_phys(cs, sm_state + 0x7f78) & 0xf0ff) << 8;

    env->gdt.base = x86_ldl_phys(cs, sm_state + 0x7f74);
    env->gdt.limit = x86_ldl_phys(cs, sm_state + 0x7f70);

    env->idt.base = x86_ldl_phys(cs, sm_state + 0x7f58);
    env->idt.limit = x86_ldl_phys(cs, sm_state + 0x7f54);

    for (i = 0; i < 6; i++) {
        if (i < 3) {
            offset = 0x7f84 + i * 12;
        } else {
            offset = 0x7f2c + (i - 3) * 12;
        }
        cpu_x86_load_seg_cache(env, i,
                               x86_ldl_phys(cs,
                                        sm_state + 0x7fa8 + i * 4) & 0xffff,
                               x86_ldl_phys(cs, sm_state + offset + 8),
                               x86_ldl_phys(cs, sm_state + offset + 4),
                               (x86_ldl_phys(cs,
                                         sm_state + offset) & 0xf0ff) << 8);
    }
    rsm_cpl(env, cr0);
    cpu_x86_update_cr4(env, x86_ldl_phys(cs, sm_state + 0x7f14));

    val = x86_ldl_phys(cs, sm_state + 0x7efc); /* revision ID */
    if (val & 0x20000) {
        env->smbase = x86_ldl_phys(cs, sm_state + 0x7ef8);
    }
}

/*
 * The shutdown of an RSM that finds invalid state (AMD64 Architecture
 * Programmer's Manual Volume 2, 24593 rev. 3.46, 10.4; Intel SDM 325462-093
 * Vol. 3C, 34.3.2), which comes before RSM returns to VMX non-root operation
 * (Intel SDM 325462-093 Vol. 3C, 34.14.2) or guest mode, as Linux 7.3's KVM
 * has it: no VM exit or #VMEXIT for it.
 */
static G_NORETURN void rsm_shutdown(CPUX86State *env, const char *reason)
{
    CPUState *cs = env_cpu(env);

    qemu_log_mask(LOG_GUEST_ERROR, "RSM: %s\n", reason);
    qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
    cs->exception_index = EXCP_HLT;
    cpu_loop_exit(cs);
}

/* What decides whether RSM restores the state in the state-save area. */
typedef struct RsmChecked {
    uint64_t cr0, cr3, cr4, efer, dr6, dr7, rflags;
    uint32_t cs_flags, ss_flags, revision;
} RsmChecked;

static void rsm_read_checked(CPUX86State *env, RsmChecked *c)
{
    CPUState *cs = env_cpu(env);
    hwaddr sm_state = env->smbase + 0x8000;

    if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM) {
        c->cr0 = x86_ldq_phys(cs, sm_state + 0x7f58);
        c->cr3 = x86_ldq_phys(cs, sm_state + 0x7f50);
        c->cr4 = x86_ldq_phys(cs, sm_state + 0x7f48);
        c->efer = x86_ldq_phys(cs, sm_state + 0x7ed0);
        c->dr6 = x86_ldq_phys(cs, sm_state + 0x7f68);
        c->dr7 = x86_ldq_phys(cs, sm_state + 0x7f60);
        c->rflags = x86_ldq_phys(cs, sm_state + 0x7f70);
        c->cs_flags = (x86_lduw_phys(cs, sm_state + 0x7e02 + R_CS * 16) &
                       0xf0ff) << 8;
        c->ss_flags = (x86_lduw_phys(cs, sm_state + 0x7e02 + R_SS * 16) &
                       0xf0ff) << 8;
    } else {
        c->cr0 = x86_ldl_phys(cs, sm_state + 0x7ffc);
        c->cr3 = x86_ldl_phys(cs, sm_state + 0x7ff8);
        c->cr4 = x86_ldl_phys(cs, sm_state + 0x7f14);
        c->efer = env->efer;
        c->dr6 = x86_ldl_phys(cs, sm_state + 0x7fcc);
        c->dr7 = x86_ldl_phys(cs, sm_state + 0x7fc8);
        c->rflags = x86_ldl_phys(cs, sm_state + 0x7ff4);
        c->cs_flags = (x86_ldl_phys(cs, sm_state + 0x7f84 + R_CS * 12) &
                       0xf0ff) << 8;
        c->ss_flags = (x86_ldl_phys(cs, sm_state + 0x7f84 + R_SS * 12) &
                       0xf0ff) << 8;
    }
    c->revision = x86_ldl_phys(cs, sm_state + 0x7efc);
}

/*
 * Why RSM shuts the processor down instead of restoring the state that C
 * describes, or NULL. Intel's processors shut down for the state of Intel
 * SDM 325462-093 Vol. 3C, 34.3.2 only, the others for that of AMD64
 * Architecture Programmer's Manual Volume 2, 24593 rev. 3.46, 10.4, where
 * EFER.SVME, as it was at the SMI, lets RSM return to paged real mode
 * (AMD64 Architecture Programmer's Manual Volume 3, 24594 rev. 3.39, RSM).
 */
static const char *rsm_invalid(CPUX86State *env, const RsmChecked *c)
{
    bool lm = env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM;
    bool lma = (c->efer & MSR_EFER_LME) && (c->cr0 & CR0_PG_MASK) &&
               (c->cr4 & CR4_PAE_MASK);
    int cpl = (c->ss_flags & DESC_DPL_MASK) >> DESC_DPL_SHIFT;
    uint64_t cr3_reserved = ~0ULL << env_archcpu(env)->phys_bits;

    if (c->cr4 & cr4_reserved_bits(env)) {
        return "reserved CR4 bits";
    }
    /* SMI put CR4.VMXE aside (Intel SDM 325462-093 Vol. 3C, 34.14.2). */
    if (c->cr4 & CR4_VMXE_MASK) {
        return "CR4.VMXE";
    }
    if ((c->cr0 & CR0_PG_MASK) && !(c->cr0 & CR0_PE_MASK) &&
        (IS_INTEL_CPU(env) || !env->smm_svme)) {
        return "CR0.PG without CR0.PE";
    }
    if ((c->cr0 & CR0_NW_MASK) && !(c->cr0 & CR0_CD_MASK)) {
        return "CR0.NW without CR0.CD";
    }
    if ((c->cr4 & CR4_CET_MASK) && !(c->cr0 & CR0_WP_MASK)) {
        return "CR4.CET without CR0.WP";
    }
    if ((c->cr4 & CR4_PCIDE_MASK) && !lma) {
        return "CR4.PCIDE outside long mode";
    }
    if (IS_INTEL_CPU(env)) {
        if ((c->cr4 & CR4_FRED_MASK) &&
            (!lma || cpl == 1 || cpl == 2 ||
             (cpl == 0 && !(c->cs_flags & DESC_L_MASK)) ||
             (cpl == 3 && (c->rflags & IOPL_MASK)))) {
            return "CR4.FRED outside 64-bit mode at CPL 0 or IOPL 0 at CPL 3";
        }
        return NULL;
    }
    if (env->features[FEAT_7_1_EAX] & CPUID_7_1_EAX_LAM) {
        cr3_reserved &= ~(CR3_LAM_U57_MASK | CR3_LAM_U48_MASK);
    }
    if ((c->cr0 >> 32) || (c->cr3 & cr3_reserved) ||
        ((c->dr6 | c->dr7) >> 32) ||
        (c->efer & ~(x86_efer_writable(env) | MSR_EFER_LMA))) {
        return "reserved bits";
    }
    if ((c->efer & MSR_EFER_LME) && (c->cr0 & CR0_PG_MASK) &&
        (!(c->cr4 & CR4_PAE_MASK) ||
         ((c->cs_flags & DESC_L_MASK) && (c->cs_flags & DESC_B_MASK)))) {
        return "an invalid return to long mode";
    }
    if ((c->rflags & VM_MASK) && (c->cr4 & CR4_CET_MASK) &&
        (env->u_cet & CET_SH_STK_EN)) {
        return "virtual-8086 mode with user shadow stacks";
    }
    if (c->revision != (lm ? SMM_REVISION_64 : SMM_REVISION_32)) {
        return "a changed SMM revision identifier";
    }
    return NULL;
}

void HELPER(rsm)(CPUX86State *env)
{
    X86CPU *cpu = env_archcpu(env);
    RsmChecked checked;
    const char *invalid;

    rsm_read_checked(env, &checked);
    invalid = rsm_invalid(env, &checked);
    if (invalid) {
        rsm_shutdown(env, invalid);
    }
    if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM) {
        rsm_load_regs_64(env);
    } else {
        rsm_load_regs_32(env);
    }

    if ((env->hflags2 & HF2_SMM_INSIDE_NMI_MASK) == 0) {
        env->hflags2 &= ~HF2_NMI_MASK;
    }
    env->hflags2 &= ~HF2_SMM_INSIDE_NMI_MASK;
    env->hflags &= ~HF_SMM_MASK;
    x86_vmx_smm_leave(env);
    tlb_flush(CPU(cpu));

    /*
     * RSM reloads the PDPTE registers from the CR3 that it restores where it
     * returns to PAE paging (AMD64 Architecture Programmer's Manual Volume 3,
     * 24594 rev. 3.39, RSM), through EPT for a guest under it; reserved bits
     * in them shut the processor down, as invalid state in the state-save
     * area does.
     */
    if (x86_pdpte_registers(env, env->cr[0], env->cr[4]) &&
        !x86_load_pdptes(env)) {
        rsm_shutdown(env, "invalid PDPTEs");
    }

    qemu_log_mask(CPU_LOG_INT, "SMM: after RSM\n");
    log_cpu_state_mask(CPU_LOG_INT, CPU(cpu), CPU_DUMP_CCOP);
}
