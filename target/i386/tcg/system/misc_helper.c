/*
 *  x86 misc helpers - system code
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
#include "qemu/main-loop.h"
#include "qemu/units.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "accel/tcg/cpu-ldst.h"
#include "accel/tcg/cpu-loop.h"
#include "accel/tcg/probe.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "exec/cputlb.h"
#include "exec/target_page.h"
#include "tcg/helper-tcg.h"
#include "hw/i386/apic.h"

void HELPER(outb)(CPUX86State *env, uint32_t port, uint32_t data)
{
    address_space_stb(&address_space_io, port, data,
                      cpu_get_mem_attrs(env), NULL);
}

target_ulong HELPER(inb)(CPUX86State *env, uint32_t port)
{
    return address_space_ldub(&address_space_io, port,
                              cpu_get_mem_attrs(env), NULL);
}

void HELPER(outw)(CPUX86State *env, uint32_t port, uint32_t data)
{
    address_space_stw_le(&address_space_io, port, data,
                         cpu_get_mem_attrs(env), NULL);
}

target_ulong HELPER(inw)(CPUX86State *env, uint32_t port)
{
    return address_space_lduw_le(&address_space_io, port,
                                 cpu_get_mem_attrs(env), NULL);
}

void HELPER(outl)(CPUX86State *env, uint32_t port, uint32_t data)
{
    address_space_stl_le(&address_space_io, port, data,
                         cpu_get_mem_attrs(env), NULL);
}

target_ulong HELPER(inl)(CPUX86State *env, uint32_t port)
{
    return address_space_ldl_le(&address_space_io, port,
                                cpu_get_mem_attrs(env), NULL);
}

target_ulong HELPER(read_cr8)(CPUX86State *env)
{
    if (x86_vmx_tpr_shadow(env)) {
        return x86_vmx_read_cr8(env);
    }
    /*
     * AVIC has CR8 be V_TPR whatever V_INTR_MASKING (AMD64 Architecture
     * Programmer's Manual Volume 2, 24593 rev. 3.45, 15.29.4.1).
     */
    if (!(env->hflags2 & HF2_VINTR_MASK) && !env->svm_avic) {
        return cpu_get_apic_tpr(env_archcpu(env)->apic_state);
    } else {
        return env->int_ctl & V_TPR_MASK;
    }
}

/*
 * The CR0 writes MOV to CR0 refuses with #GP: reserved bits 63:32, PG
 * without PE, NW without CD, clearing PG in 64-bit mode or with CR4.PCIDE
 * set, and turning on IA-32e mode without PAE, from code with CS.L, or with
 * a 16-bit TSS in TR, and in VMX root operation what IA32_VMX_CR0_FIXED0 and
 * FIXED1 do not allow
 * (Intel SDM 325462-093 Vol. 2B, MOV, Move to/from Control Registers; AMD64
 * Architecture Programmer's Manual Volume 3, 24594 rev. 3.38, MOV CRn).
 * The reserved bits of CR0[31:0] are ignored.
 */
static bool cr0_valid(CPUX86State *env, uint64_t cr0)
{
    /*
     * CR0.WP cannot be cleared while CR4.CET is set (Intel SDM 325462-093
     * Vol. 3A, 2.5).
     */
    if ((cr0 >> 32) ||
        ((cr0 & CR0_PG_MASK) && !(cr0 & CR0_PE_MASK)) ||
        ((cr0 & CR0_NW_MASK) && !(cr0 & CR0_CD_MASK)) ||
        ((env->cr[4] & CR4_CET_MASK) && !(cr0 & CR0_WP_MASK))) {
        return false;
    }
    if (env->vmx.on && !x86_vmx_cr_valid(env, 0, cr0)) {
        return false;
    }
#ifdef TARGET_X86_64
    if (((env->hflags & HF_CS64_MASK) || (env->cr[4] & CR4_PCIDE_MASK)) &&
        !(cr0 & CR0_PG_MASK)) {
        return false;
    }
    if (!(env->cr[0] & CR0_PG_MASK) && (cr0 & CR0_PG_MASK) &&
        (env->efer & MSR_EFER_LME) &&
        (!(env->cr[4] & CR4_PAE_MASK) ||
         (env->segs[R_CS].flags & DESC_L_MASK) ||
         !(env->tr.flags & (8 << DESC_TYPE_SHIFT)))) {
        return false;
    }
#endif
    return true;
}

/*
 * The CR4 writes MOV to CR4 refuses with #GP: reserved bits, which include
 * those of absent features, a change of LA57 or clearing PAE in IA-32e
 * mode, setting PCIDE outside IA-32e mode or with CR3[11:0] not 0 (the same
 * documents), setting CET without CR0.WP (Intel SDM 325462-093 Vol. 3A,
 * 2.5), and in VMX root operation what IA32_VMX_CR4_FIXED0 and FIXED1 do
 * not allow.
 */
static bool cr4_valid(CPUX86State *env, uint64_t cr4)
{
    if ((cr4 & cr4_reserved_bits(env)) ||
        ((cr4 & CR4_CET_MASK) && !(env->cr[0] & CR0_WP_MASK))) {
        return false;
    }
    if (env->vmx.on && !x86_vmx_cr_valid(env, 4, cr4)) {
        return false;
    }
    if ((cr4 & ~env->cr[4] & CR4_PCIDE_MASK) &&
        (!(env->efer & MSR_EFER_LMA) || (env->cr[3] & 0xfff))) {
        return false;
    }
    if ((env->efer & MSR_EFER_LMA) &&
        (((cr4 ^ env->cr[4]) & CR4_LA57_MASK) || !(cr4 & CR4_PAE_MASK))) {
        return false;
    }
    return true;
}

/* MOV from CR0 or CR4, and SMSW, in guest mode. */
target_ulong HELPER(read_crN)(CPUX86State *env, int reg)
{
    if (env->vmx.nonroot) {
        return x86_vmx_cr_read(env, reg);
    }
    return env->cr[reg];
}

/*
 * LMSW in guest mode: CR0.PE, MP, EM, and TS from the source, which
 * cannot clear PE; mem is whether the source is in memory.
 */
void HELPER(lmsw)(CPUX86State *env, target_ulong src, int mem)
{
    uint32_t cr0 = (env->cr[0] & ~0xe) | (src & 0xf);

    if (env->vmx.nonroot) {
        cr0 = x86_vmx_lmsw(env, src & 0xffff, mem, GETPC());
    }
    cpu_x86_update_cr0(env, cr0);
}

/*
 * Whether a MOV to CR that leaves CR0 at CR0 and CR4 at CR4 loads the PDPTE
 * registers: where PAE paging is then in use and the move changes CR0.CD,
 * NW, or PG, or CR4.PAE, PGE, PSE, or SMEP, or loads CR3 (Intel SDM
 * 325462-093 Vol. 3A, 5.4.1), but not under nested paging, where walks read
 * the guest's PDPTEs (AMD64 Architecture Programmer's Manual Volume 2,
 * 24593 rev. 3.45, 15.25.10).
 */
static bool cr_loads_pdptes(CPUX86State *env, int reg, uint64_t cr0,
                            uint64_t cr4)
{
    if (!x86_pae_paging(cr0, cr4, env->efer) ||
        ((env->hflags2 & HF2_NPT_MASK) && !env->vmx.nonroot)) {
        return false;
    }
    return reg == 3 ||
           ((cr0 ^ env->cr[0]) & (CR0_CD_MASK | CR0_NW_MASK | CR0_PG_MASK)) ||
           ((cr4 ^ env->cr[4]) &
            (CR4_PAE_MASK | CR4_PGE_MASK | CR4_PSE_MASK | CR4_SMEP_MASK));
}

/*
 * The PDPTEs at CR3 for the PDPTE registers, false where a present one sets
 * a reserved bit, 2:1, 8:5, or 63:MAXPHYADDR (Intel SDM 325462-093 Vol. 3A,
 * 5.4.1 and Table 5-8). Under EPT, CR3 is translated as a read (Intel SDM
 * 325462-093 Vol. 3C, 31.3.1), where a violation, misconfiguration, or
 * log-full event exits from the instruction at RA.
 */
bool x86_read_pdptes(CPUX86State *env, uint64_t cr3, uint64_t *pdpte,
                     uintptr_t ra)
{
    uint64_t reserved = 0x1e6 | ~0ULL << env_archcpu(env)->phys_bits;
    hwaddr base = cr3 & 0xffffffe0;

    if (x86_vmx_ept_active(env)) {
        hwaddr hpa;
        int prot, size;

        if (!x86_vmx_ept_translate(env, base, MMU_DATA_LOAD, false, &hpa,
                                   &prot, &size)) {
            x86_vmx_pdpte_exit(env, base, ra);
        }
        base = hpa;
    } else {
        base &= x86_get_a20_mask(env);
    }
    for (int i = 0; i < 4; i++) {
        pdpte[i] = x86_ldq_phys(env_cpu(env), base + 8 * i);
        if ((pdpte[i] & PG_PRESENT_MASK) && (pdpte[i] & reserved)) {
            return false;
        }
    }
    return true;
}

/*
 * Loads the PDPTE registers from the PDPTEs at CR3, unless they set reserved
 * bits, for what loads them along with CR3 (Intel SDM 325462-093 Vol. 3A,
 * 5.11.1; AMD64 Architecture Programmer's Manual Volume 2, 24593 rev. 3.45,
 * 15.5.1 and 15.6).
 */
bool x86_load_pdptes(CPUX86State *env)
{
    uint64_t pdpte[4];

    if (!x86_read_pdptes(env, env->cr[3], pdpte, 0)) {
        return false;
    }
    memcpy(env->pdpte, pdpte, sizeof(pdpte));
    env->pdpte_loaded = true;
    return true;
}

void HELPER(write_crN)(CPUX86State *env, int reg, target_ulong t0)
{
    uint64_t pdpte[4];
    bool load = false;

    if (env->vmx.nonroot) {
        t0 = x86_vmx_cr_write(env, reg, t0, env->svm_decode_info & 0xf,
                              GETPC());
    }
    switch (reg) {
    case 0:
        if (!cr0_valid(env, t0)) {
            raise_exception_ra(env, EXCP0D_GPF, GETPC());
        }
        t0 &= CR0_DEFINED_MASK;
        x86_svm_late_intercept(env, SVM_EXIT_WRITE_CR0, GETPC());
        /*
        * If we reach this point, the CR0 write intercept is disabled.
        * But we could still exit if the hypervisor has requested the selective
        * intercept for bits other than TS and MP
        */
        if (cpu_svm_has_intercept(env, SVM_EXIT_CR0_SEL_WRITE) &&
            ((env->cr[0] ^ t0) & ~(CR0_TS_MASK | CR0_MP_MASK))) {
            cpu_vmexit(env, SVM_EXIT_CR0_SEL_WRITE, env->svm_decode_info,
                       GETPC());
        }
        load = cr_loads_pdptes(env, 0, t0, env->cr[4]);
        if (load && !x86_read_pdptes(env, env->cr[3], pdpte, GETPC())) {
            raise_exception_ra(env, EXCP0D_GPF, GETPC());
        }
        cpu_x86_update_cr0(env, t0);
        break;
    case 3:
#ifdef TARGET_X86_64
        /*
         * With CR4.PCIDE, bit 63 lets the new PCID's translations stay,
         * which QEMU's TLB, holding the current PCID's only, drops anyway,
         * as the processor may (Intel SDM 325462-093 Vol. 3A, 5.10.4.1).
         */
        if (env->cr[4] & CR4_PCIDE_MASK) {
            t0 &= ~(1ULL << 63);
        }
#endif
        if (env->efer & MSR_EFER_LMA) {
            uint64_t reserved = (~0ULL) << env_archcpu(env)->phys_bits;

            if (env->features[FEAT_7_1_EAX] & CPUID_7_1_EAX_LAM) {
                reserved &= ~(CR3_LAM_U57_MASK | CR3_LAM_U48_MASK);
            }
            if (t0 & reserved) {
                raise_exception_ra(env, EXCP0D_GPF, GETPC());
            }
        } else {
            t0 &= 0xffffffffUL;
        }
        x86_svm_late_intercept(env, SVM_EXIT_WRITE_CR0 + 3, GETPC());
        load = cr_loads_pdptes(env, 3, env->cr[0], env->cr[4]);
        if (load && !x86_read_pdptes(env, t0, pdpte, GETPC())) {
            raise_exception_ra(env, EXCP0D_GPF, GETPC());
        }
        cpu_x86_update_cr3(env, t0);
        break;
    case 4:
        if (!cr4_valid(env, t0)) {
            raise_exception_ra(env, EXCP0D_GPF, GETPC());
        }
        x86_svm_late_intercept(env, SVM_EXIT_WRITE_CR0 + 4, GETPC());
        load = cr_loads_pdptes(env, 4, env->cr[0], t0);
        if (load && !x86_read_pdptes(env, env->cr[3], pdpte, GETPC())) {
            raise_exception_ra(env, EXCP0D_GPF, GETPC());
        }
        cpu_x86_update_cr4(env, t0);
        break;
    case 8:
        if (t0 & ~(target_ulong)0xf) {
            raise_exception_ra(env, EXCP0D_GPF, GETPC());
        }
        x86_svm_late_intercept(env, SVM_EXIT_WRITE_CR0 + 8, GETPC());
        if (x86_vmx_tpr_shadow(env)) {
            x86_vmx_write_cr8(env, t0, GETPC());
            break;
        }
        /* Under AVIC, CR8 writes V_TPR and the backing page's TPR. */
        if (env->svm_avic) {
            svm_avic_set_tpr(env, (t0 & V_TPR_MASK) << 4);
            break;
        }
        if (!(env->hflags2 & HF2_VINTR_MASK)) {
            bql_lock();
            cpu_set_apic_tpr(env_archcpu(env)->apic_state, t0);
            bql_unlock();
        }
        env->int_ctl = (env->int_ctl & ~V_TPR_MASK) | (t0 & V_TPR_MASK);

        CPUState *cs = env_cpu(env);
        if (ctl_has_irq(env)) {
            /*
             * cpu_interrupt() needs the BQL; from the vCPU's own thread it
             * only has to end the current TB as well.
             */
            cpu_set_interrupt(cs, CPU_INTERRUPT_VIRQ);
            qatomic_set(&cs->neg.icount_decr.u16.high, -1);
        } else {
            cpu_reset_interrupt(cs, CPU_INTERRUPT_VIRQ);
        }
        break;
    default:
        x86_svm_late_intercept(env, SVM_EXIT_WRITE_CR0 + reg, GETPC());
        env->cr[reg] = t0;
        break;
    }
    /* The updates above dropped the PDPTE registers the move loads. */
    if (load) {
        memcpy(env->pdpte, pdpte, sizeof(pdpte));
        env->pdpte_loaded = true;
    }
}

/* The TSC Ratio MSR exists where CPUID Fn8000_000A_EDX shows TscRateMsr. */
static bool tsc_ratio_present(CPUX86State *env)
{
    return (env->features[FEAT_8000_0001_ECX] & CPUID_EXT3_SVM) &&
           (env->features[FEAT_SVM] & CPUID_SVM_TSCSCALE);
}

/* The local APIC's TSC deadline comes at another time once the TSC moved. */
static void tsc_changed(CPUX86State *env)
{
    if (env_archcpu(env)->apic_state) {
        BQL_LOCK_GUARD();

        apic_tsc_changed(env_archcpu(env)->apic_state);
    }
}

/*
 * The IA32_SPEC_CTRL bits CPUID shows (Intel SDM 325462-093 Vol. 4, Table
 * 2-2; APM 24593 rev. 3.45, 3.2.9); the MSR exists where any is. TCG does
 * not speculate, so the controls need only keep their values.
 */
static uint64_t spec_ctrl_bits(CPUX86State *env)
{
    uint32_t edx7 = env->features[FEAT_7_0_EDX];
    uint32_t edx7_2 = env->features[FEAT_7_2_EDX];
    uint32_t ebx8 = env->features[FEAT_8000_0008_EBX];
    uint64_t bits = 0;

    if ((edx7 & CPUID_7_0_EDX_SPEC_CTRL) ||
        (ebx8 & CPUID_8000_0008_EBX_IBRS)) {
        bits |= SPEC_CTRL_IBRS;
    }
    if ((edx7 & CPUID_7_0_EDX_STIBP) || (ebx8 & CPUID_8000_0008_EBX_STIBP)) {
        bits |= SPEC_CTRL_STIBP;
    }
    if ((edx7 & CPUID_7_0_EDX_SPEC_CTRL_SSBD) ||
        (ebx8 & CPUID_8000_0008_EBX_AMD_SSBD)) {
        bits |= SPEC_CTRL_SSBD;
    }
    if (edx7_2 & CPUID_7_2_EDX_IPRED_CTRL) {
        bits |= SPEC_CTRL_IPRED_DIS;
    }
    if (edx7_2 & CPUID_7_2_EDX_RRSBA_CTRL) {
        bits |= SPEC_CTRL_RRSBA_DIS;
    }
    if ((edx7_2 & CPUID_7_2_EDX_PSFD) ||
        (ebx8 & CPUID_8000_0008_EBX_AMD_PSFD)) {
        bits |= SPEC_CTRL_PSFD;
    }
    if (edx7_2 & CPUID_7_2_EDX_DDPD_U) {
        bits |= SPEC_CTRL_DDPD_U;
    }
    if (edx7_2 & CPUID_7_2_EDX_BHI_CTRL) {
        bits |= SPEC_CTRL_BHI_DIS_S;
    }
    return bits;
}

/* The IA32_PRED_CMD barriers CPUID shows, which have nothing to clear. */
static uint64_t pred_cmd_bits(CPUX86State *env)
{
    uint64_t bits = 0;

    if ((env->features[FEAT_7_0_EDX] & CPUID_7_0_EDX_SPEC_CTRL) ||
        (env->features[FEAT_8000_0008_EBX] & CPUID_8000_0008_EBX_IBPB)) {
        bits |= PRED_CMD_IBPB;
    }
    if (env->features[FEAT_8000_0021_EAX] & CPUID_8000_0021_EAX_SBPB) {
        bits |= PRED_CMD_SBPB;
    }
    return bits;
}

/* The IA32_EFER bits WRMSR changes; LMA follows CR0.PG and LME. */
uint64_t x86_efer_writable(CPUX86State *env)
{
    uint64_t mask = 0;

    if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_SYSCALL) {
        mask |= MSR_EFER_SCE;
    }
    if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM) {
        mask |= MSR_EFER_LME;
    }
    if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_FFXSR) {
        mask |= MSR_EFER_FFXSR;
    }
    if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_NX) {
        mask |= MSR_EFER_NXE;
    }
    if (env->features[FEAT_8000_0001_ECX] & CPUID_EXT3_SVM) {
        mask |= MSR_EFER_SVME;
    }
    return mask;
}

/*
 * The CPUID registers that AMD's CPUID override MSR index (MSRC001_1002 +
 * index) controls, OSXSAVE and APIC as fields whatever CR4 and the local
 * APIC's state, and without the hypervisor bit, which the processor's
 * CPUID does not have (PPR for AMD Family 17h Model 20h, 55772 rev. 3.08,
 * MSRC001_1002 to MSRC001_1005).
 */
static uint64_t amd_cpuid_override_bits(CPUX86State *env, int index)
{
    uint32_t eax, ebx, ecx, edx;

    switch (index) {
    case 0:
        if (env->cpuid_level < 7) {
            return 0;
        }
        cpu_x86_cpuid(env, 7, 0, &eax, &ebx, &ecx, &edx);
        return (uint64_t)eax << 32 | ebx;
    case 1:
        if (env->cpuid_level < 6) {
            return 0;
        }
        cpu_x86_cpuid(env, 6, 0, &eax, &ebx, &ecx, &edx);
        return ecx;
    case 2:
        cpu_x86_cpuid(env, 1, 0, &eax, &ebx, &ecx, &edx);
        ecx &= ~CPUID_EXT_HYPERVISOR;
        if (ecx & CPUID_EXT_XSAVE) {
            ecx |= CPUID_EXT_OSXSAVE;
        }
        edx |= env->features[FEAT_1_EDX] & CPUID_APIC;
        return (uint64_t)ecx << 32 | edx;
    default:
        cpu_x86_cpuid(env, 0x80000001, 0, &eax, &ebx, &ecx, &edx);
        edx |= env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_APIC;
        return (uint64_t)ecx << 32 | edx;
    }
}

/*
 * What CPUID shows of the bits that those MSRs clear: nothing; setting
 * bits back shows them again, but none that the CPU lacks.
 */
void x86_amd_cpuid_hide(CPUX86State *env, uint32_t leaf, uint32_t subleaf,
                        uint32_t *eax, uint32_t *ebx, uint32_t *ecx,
                        uint32_t *edx)
{
    const uint64_t *hidden = env->amd_cpuid_hidden;

    if (leaf == 7 && subleaf == 0 && env->cpuid_level >= 7) {
        *eax &= ~(uint32_t)(hidden[0] >> 32);
        *ebx &= ~(uint32_t)hidden[0];
    } else if (leaf == 6 && env->cpuid_level >= 6) {
        *ecx &= ~(uint32_t)hidden[1];
    } else if (leaf == 1) {
        *ecx &= ~(uint32_t)(hidden[2] >> 32);
        *edx &= ~(uint32_t)hidden[2];
    } else if (leaf == 0x80000001 && env->cpuid_xlevel >= 0x80000001) {
        *ecx &= ~(uint32_t)(hidden[3] >> 32);
        *edx &= ~(uint32_t)hidden[3];
    }
}

/*
 * WRMSR's effect, false where it raises #GP; VM entries and exits load
 * their MSR areas with it, exits with the BQL held, hence BQL_LOCK_GUARD()
 * here and in x86_cpu_rdmsr().
 */
bool x86_cpu_wrmsr(CPUX86State *env, uint32_t msr, uint64_t val)
{
    CPUState *cs = env_cpu(env);
    int pmu = x86_pmu_wrmsr(env, msr, val);
    int uintr;

    if (pmu >= 0) {
        return pmu;
    }
    uintr = x86_uintr_wrmsr(env, msr, val);
    if (uintr >= 0) {
        return uintr;
    }
#ifdef TARGET_X86_64
    uintr = x86_fred_wrmsr(env, msr, val);
    if (uintr >= 0) {
        return uintr;
    }
#endif
    switch (msr) {
    case MSR_IA32_SYSENTER_CS:
        env->sysenter_cs = val & 0xffff;
        break;
    /*
     * The MSRs holding linear addresses take canonical ones only (Intel SDM
     * 325462-093 Vol. 3A, 4.5.3), the SYSENTER ones on Intel only, where
     * SYSENTER works in 64-bit mode.
     */
    case MSR_IA32_SYSENTER_ESP:
        if (IS_INTEL_CPU(env) && !x86_canonical(env, val, false)) {
            return false;
        }
        env->sysenter_esp = val;
        break;
    case MSR_IA32_SYSENTER_EIP:
        if (IS_INTEL_CPU(env) && !x86_canonical(env, val, false)) {
            return false;
        }
        env->sysenter_eip = val;
        break;
    case MSR_IA32_APICBASE: {
        int ret;

        if (val & MSR_IA32_APICBASE_RESERVED) {
            return false;
        }

        ret = cpu_set_apic_base(env_archcpu(env)->apic_state, val);
        if (ret < 0) {
            return false;
        }
        break;
    }
    case MSR_EFER: {
        uint64_t update_mask = x86_efer_writable(env);
        uint64_t old = env->efer;

        cpu_load_efer(env, (env->efer & ~update_mask) | (val & update_mask));
        if (((old ^ env->efer) & MSR_EFER_SVME) && x86_pmu_enabled(env)) {
            x86_pmu_reconfigure(env);
        }
        break;
    }
    case MSR_STAR:
        env->star = val;
        break;
    case MSR_PAT:
        env->pat = val;
        break;
    case MSR_IA32_PKRS:
        if (val & 0xFFFFFFFF00000000ull) {
            return false;
        }
        env->pkrs = val;
        tlb_flush(cs);
        break;
    case MSR_VM_HSAVE_PA:
        if (val & (0xfff | ((~0ULL) << env_archcpu(env)->phys_bits))) {
            return false;
        }
        env->vm_hsave = val;
        break;
#ifdef TARGET_X86_64
    case MSR_LSTAR:
        if (!x86_canonical(env, val, false)) {
            return false;
        }
        env->lstar = val;
        break;
    case MSR_CSTAR:
        if (!x86_canonical(env, val, false)) {
            return false;
        }
        env->cstar = val;
        break;
    case MSR_FMASK:
        env->fmask = val;
        break;
    case MSR_FSBASE:
        if (!x86_canonical(env, val, false)) {
            return false;
        }
        env->segs[R_FS].base = val;
        break;
    case MSR_GSBASE:
        if (!x86_canonical(env, val, false)) {
            return false;
        }
        env->segs[R_GS].base = val;
        break;
    case MSR_KERNELGSBASE:
        if (!x86_canonical(env, val, false)) {
            return false;
        }
        env->kernelgsbase = val;
        break;
#endif
    case MSR_MTRRphysBase(0):
    case MSR_MTRRphysBase(1):
    case MSR_MTRRphysBase(2):
    case MSR_MTRRphysBase(3):
    case MSR_MTRRphysBase(4):
    case MSR_MTRRphysBase(5):
    case MSR_MTRRphysBase(6):
    case MSR_MTRRphysBase(7):
        env->mtrr_var[(msr -
                       MSR_MTRRphysBase(0)) / 2].base = val;
        break;
    case MSR_MTRRphysMask(0):
    case MSR_MTRRphysMask(1):
    case MSR_MTRRphysMask(2):
    case MSR_MTRRphysMask(3):
    case MSR_MTRRphysMask(4):
    case MSR_MTRRphysMask(5):
    case MSR_MTRRphysMask(6):
    case MSR_MTRRphysMask(7):
        env->mtrr_var[(msr -
                       MSR_MTRRphysMask(0)) / 2].mask = val;
        break;
    case MSR_MTRRfix64K_00000:
        env->mtrr_fixed[msr -
                        MSR_MTRRfix64K_00000] = val;
        break;
    case MSR_MTRRfix16K_80000:
    case MSR_MTRRfix16K_A0000:
        env->mtrr_fixed[msr -
                        MSR_MTRRfix16K_80000 + 1] = val;
        break;
    case MSR_MTRRfix4K_C0000:
    case MSR_MTRRfix4K_C8000:
    case MSR_MTRRfix4K_D0000:
    case MSR_MTRRfix4K_D8000:
    case MSR_MTRRfix4K_E0000:
    case MSR_MTRRfix4K_E8000:
    case MSR_MTRRfix4K_F0000:
    case MSR_MTRRfix4K_F8000:
        env->mtrr_fixed[msr -
                        MSR_MTRRfix4K_C0000 + 3] = val;
        break;
    case MSR_MTRRdefType:
        env->mtrr_deftype = val;
        break;
    case MSR_MCG_STATUS:
        env->mcg_status = val;
        break;
    /*
     * The Pentium's machine-check MSRs (Intel SDM 325462-093 Vol. 4, Table
     * 2-2) read 0 and refuse writes, as Linux 7.3's KVM has them
     * (get_msr_mce()).
     */
    case MSR_P5_MC_ADDR:
    case MSR_P5_MC_TYPE:
        return false;
    case MSR_MCG_CTL:
        if ((env->mcg_cap & MCG_CTL_P)
            && (val == 0 || val == ~(uint64_t)0)) {
            env->mcg_ctl = val;
        }
        break;
    case MSR_IA32_TSC: {
        /*
         * The counter takes the value written, not scaled or offset, and
         * IA32_TSC_ADJUST moves as far; a write of IA32_TSC_ADJUST moves
         * the counter as far as it moves (Intel SDM 325462-093 Vol. 3B,
         * 20.17.3).
         */
        int64_t delta = val - cpu_get_tsc(env);

        env->tsc_adjust += delta - env->tsc_written_delta;
        env->tsc_written_delta = delta;
        tsc_changed(env);
        break;
    }
    case MSR_TSC_ADJUST:
        if (!(env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_TSC_ADJUST)) {
            return false;
        }
        env->tsc_written_delta += val - env->tsc_adjust;
        env->tsc_adjust = val;
        tsc_changed(env);
        break;
    case MSR_IA32_TSCDEADLINE: {
        BQL_LOCK_GUARD();

        if (!(env->features[FEAT_1_ECX] & CPUID_EXT_TSC_DEADLINE_TIMER)) {
            return false;
        }
        apic_set_tsc_deadline(env_archcpu(env)->apic_state, val);
        break;
    }
    case MSR_TSC_AUX:
        env->tsc_aux = val;
        break;
    case MSR_AMD64_TSC_RATIO:
        if (!tsc_ratio_present(env) || (val & MSR_AMD64_TSC_RATIO_RESERVED)) {
            return false;
        }
        env->amd_tsc_scale_msr = val;
        break;
    case MSR_AMD64_AVIC_DOORBELL:
        /*
         * A doorbell to the processor whose APIC ID bits 7:0 give (AMD64
         * Architecture Programmer's Manual Volume 2, 24593 rev. 3.45,
         * 15.29.8.2).
         */
        if (!(env->features[FEAT_SVM] & CPUID_SVM_AVIC) || (val >> 8)) {
            return false;
        }
        svm_avic_doorbell(env, val);
        break;
    case MSR_IA32_MISC_ENABLE:
        env->msr_ia32_misc_enable = val;
        break;
    case MSR_IA32_DEBUGCTL:
        if (val & ~(DEBUGCTL_LBR | DEBUGCTL_BTF)) {
            return false;
        }
        env->debugctl = val;
        break;
    case MSR_LASTBRANCH_FROM_IP ... MSR_LASTINT_TO_IP:
        /* Read-only. */
        return false;
    case MSR_IA32_BNDCFGS:
        /* Bits 11:2 are reserved, and the base is a linear address. */
        if ((val & 0xffc) || !x86_canonical(env, val & ~0xfffULL, false)) {
            return false;
        }
        env->msr_bndcfgs = val;
        cpu_sync_bndcs_hflags(env);
        break;
    /*
     * IA32_U_CET and IA32_S_CET exist with either CET feature, the shadow
     * stack pointers and their table with shadow stacks (Intel SDM
     * 325462-093 Vol. 4, Table 2-2).
     */
    case MSR_IA32_U_CET:
    case MSR_IA32_S_CET:
        if ((!x86_has_shstk(env) && !x86_has_ibt(env)) ||
            !x86_cet_msr_valid(env, msr, val)) {
            return false;
        }
        if (msr == MSR_IA32_U_CET) {
            env->u_cet = val;
        } else {
            env->s_cet = val;
        }
        break;
    case MSR_IA32_PL0_SSP:
    case MSR_IA32_PL1_SSP:
    case MSR_IA32_PL2_SSP:
    case MSR_IA32_PL3_SSP:
        if (!x86_has_pl_ssp(env, msr) || !x86_cet_msr_valid(env, msr, val)) {
            return false;
        }
        *x86_pl_ssp(env, msr - MSR_IA32_PL0_SSP) = val;
        break;
#ifdef TARGET_X86_64
    case MSR_IA32_INT_SSP_TAB:
        if (!x86_has_shstk(env) || !x86_cet_msr_valid(env, msr, val)) {
            return false;
        }
        env->int_ssp_table = val;
        break;
#endif
    case MSR_MISC_FEATURES_ENABLES:
        /*
         * Bit 0 makes CPUID fault at CPL > 0 (Intel SDM 325462-093 Vol. 4,
         * Table 2-53), which MSR_PLATFORM_INFO says it can.
         */
        if (!IS_INTEL_CPU(env) || (val & ~MISC_FEATURES_CPUID_FAULT)) {
            return false;
        }
        env->msr_misc_features_enables = val;
        break;
    case MSR_K7_HWCR:
        /*
         * CpuidUserDis makes CPUID fault at CPL > 0 (AMD64 Architecture
         * Programmer's Manual Volume 2, 24593 rev. 3.45, 3.2.10).
         */
        if ((val & HWCR_CPUID_USER_DIS) &&
            !(env->features[FEAT_8000_0021_EAX] &
              CPUID_8000_0021_EAX_CPUID_USER_DIS)) {
            return false;
        }
        env->msr_hwcr = val;
        break;
    case MSR_AMD_CPUID_7_FEATURES ... MSR_AMD_CPUID_EXT_FEATURES: {
        int index = msr - MSR_AMD_CPUID_7_FEATURES;

        if (!IS_AMD_CPU(env)) {
            return false;
        }
        env->amd_cpuid_hidden[index] = amd_cpuid_override_bits(env, index) &
                                       ~val;
        break;
    }
    case MSR_DR0_ADDR_MASK:
    case MSR_DR1_ADDR_MASK ... MSR_DR1_ADDR_MASK + 2: {
        int index = msr == MSR_DR0_ADDR_MASK ? 0 :
                    msr - MSR_DR1_ADDR_MASK + 1;

        /* Bits 63:32 are reserved. */
        if (!x86_dr_addr_mask_exists(env, index) || (val >> 32)) {
            return false;
        }
        x86_set_dr_addr_mask(env, index, val);
        break;
    }
    case MSR_IA32_XSS:
        /*
         * It may hold the supervisor state components CPUID.(EAX=0DH,
         * ECX=1):EDX:ECX lists (Intel SDM 325462-093 Vol. 1, 13.2).
         */
        if (!(env->features[FEAT_XSAVE] & CPUID_XSAVE_XSAVES) ||
            (val & ~((uint64_t)env->features[FEAT_XSAVE_XSS_HI] << 32 |
                     env->features[FEAT_XSAVE_XSS_LO]))) {
            return false;
        }
        env->xss = val;
        break;
    case MSR_IA32_UMWAIT_CONTROL:
        /*
         * Bits 31:2, the limit of UMWAIT's and TPAUSE's waits, and 0, C0.2
         * not allowed (Intel SDM 325462-093 Vol. 2B, UMWAIT); bit 1 and
         * bits 63:32 are reserved, as Linux 7.3's KVM treats them.
         */
        if (!(env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_WAITPKG) ||
            (val & ~0xfffffffdull)) {
            return false;
        }
        env->umwait = val;
        break;
    case MSR_APIC_START ... MSR_APIC_END: {
        int ret;
        int index = msr - MSR_APIC_START;

        {
            BQL_LOCK_GUARD();

            ret = apic_msr_write(env_archcpu(env)->apic_state, index, val);
        }
        if (ret < 0) {
            return false;
        }

        break;
    }
    case MSR_IA32_FEATURE_CONTROL:
        if (!x86_feature_control_exists(env) ||
            !x86_feature_control_write(env, val)) {
            return false;
        }
        break;
    case MSR_IA32_VMX_BASIC ... MSR_IA32_VMX_EXIT_CTLS2:
    case MSR_IA32_ARCH_CAPABILITIES:
    case MSR_IA32_XAPIC_DISABLE_STATUS:
        /* Read-only (Intel SDM 325462-093 Vol. 4, Table 2-2). */
        return false;
    case MSR_IA32_SPEC_CTRL:
        if (!spec_ctrl_bits(env) || (val & ~spec_ctrl_bits(env))) {
            return false;
        }
        env->spec_ctrl = val;
        break;
    case MSR_IA32_PRED_CMD:
        if (!pred_cmd_bits(env) || (val & ~pred_cmd_bits(env))) {
            return false;
        }
        break;
    case MSR_IA32_FLUSH_CMD:
        if (!(env->features[FEAT_7_0_EDX] & CPUID_7_0_EDX_FLUSH_L1D) ||
            (val & ~FLUSH_CMD_L1D_FLUSH)) {
            return false;
        }
        break;
    default:
        if (msr >= MSR_MC0_CTL
            && msr < MSR_MC0_CTL + 4 * 32) {
            uint32_t offset = msr - MSR_MC0_CTL;

            /* Banks past MCG_CAP.Count do not exist. */
            if (offset >= 4 * (env->mcg_cap & MCG_CAP_BANKS_MASK)) {
                return false;
            }
            /*
             * MCi_CTL takes 0 or all ones, bits 10 and 0 aside, as Linux
             * 7.3's KVM has it for guests that clear them; MCi_STATUS takes
             * 0 only (Intel SDM 325462-093 Vol. 3B, 18.3.2.2) unless AMD's
             * HWCR.McStatusWrEn allows others (PPR for AMD Family 17h Model
             * 20h, 55772 rev. 3.08, MSRC001_0015).
             */
            if ((offset & 0x3) == 0 && val &&
                (val | (1ULL << 10) | 1) != ~(uint64_t)0) {
                return false;
            }
            if ((offset & 0x3) == 1 && val &&
                !(env->msr_hwcr & HWCR_MC_STATUS_WR_EN)) {
                return false;
            }
            env->mce_banks[offset] = val;
            break;
        }
        /* XXX: exception? */
        break;
    }
    return true;
}

void HELPER(wrmsr)(CPUX86State *env)
{
    uint64_t val;
    bool ok;

    cpu_svm_check_intercept_param(env, SVM_EXIT_MSR, 1, GETPC());

    val = ((uint32_t)env->regs[R_EAX]) |
        ((uint64_t)((uint32_t)env->regs[R_EDX]) << 32);

    if (unlikely(env->svm_x2avic) &&
        (uint32_t)env->regs[R_ECX] >= MSR_APIC_START &&
        (uint32_t)env->regs[R_ECX] <= MSR_APIC_END) {
        if (!svm_x2avic_wrmsr(env, env->regs[R_ECX], val, GETPC())) {
            raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
        }
        return;
    }
    if (unlikely(env->vmx.nonroot) &&
        x86_vmx_x2apic_wrmsr(env, env->regs[R_ECX], val, GETPC())) {
        return;
    }

    /* WRMSR has not retired for the PMU it accesses. */
    env->pmu.unretired = 1;
    ok = x86_cpu_wrmsr(env, (uint32_t)env->regs[R_ECX], val);
    env->pmu.unretired = 0;
    if (!ok) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }
}

/* RDMSR's value, false where it raises #GP. */
bool x86_cpu_rdmsr(CPUX86State *env, uint32_t msr, uint64_t *valp)
{
    X86CPU *x86_cpu = env_archcpu(env);
    uint64_t val;
    int pmu = x86_pmu_rdmsr(env, msr, valp);
    int uintr;

    if (pmu >= 0) {
        return pmu;
    }
    uintr = x86_uintr_rdmsr(env, msr, valp);
    if (uintr >= 0) {
        return uintr;
    }
#ifdef TARGET_X86_64
    uintr = x86_fred_rdmsr(env, msr, valp);
    if (uintr >= 0) {
        return uintr;
    }
#endif
    switch (msr) {
    case MSR_IA32_SYSENTER_CS:
        val = env->sysenter_cs;
        break;
    case MSR_IA32_SYSENTER_ESP:
        val = env->sysenter_esp;
        break;
    case MSR_IA32_SYSENTER_EIP:
        val = env->sysenter_eip;
        break;
    case MSR_IA32_APICBASE:
        val = cpu_get_apic_base(env_archcpu(env)->apic_state);
        break;
    case MSR_EFER:
        val = env->efer;
        break;
    case MSR_STAR:
        val = env->star;
        break;
    case MSR_PAT:
        val = env->pat;
        break;
    case MSR_IA32_PKRS:
        val = env->pkrs;
        break;
    case MSR_VM_HSAVE_PA:
        val = env->vm_hsave;
        break;
    case MSR_IA32_PERF_STATUS:
        /* tsc_increment_by_tick */
        val = 1000ULL;
        /* CPU multiplier */
        val |= (((uint64_t)4ULL) << 40);
        break;
#ifdef TARGET_X86_64
    case MSR_LSTAR:
        val = env->lstar;
        break;
    case MSR_CSTAR:
        val = env->cstar;
        break;
    case MSR_FMASK:
        val = env->fmask;
        break;
    case MSR_FSBASE:
        val = env->segs[R_FS].base;
        break;
    case MSR_GSBASE:
        val = env->segs[R_GS].base;
        break;
    case MSR_KERNELGSBASE:
        val = env->kernelgsbase;
        break;
    case MSR_TSC_AUX:
        val = env->tsc_aux;
        break;
#endif
    case MSR_SMI_COUNT:
        val = env->msr_smi_count;
        break;
    case MSR_MTRRphysBase(0):
    case MSR_MTRRphysBase(1):
    case MSR_MTRRphysBase(2):
    case MSR_MTRRphysBase(3):
    case MSR_MTRRphysBase(4):
    case MSR_MTRRphysBase(5):
    case MSR_MTRRphysBase(6):
    case MSR_MTRRphysBase(7):
        val = env->mtrr_var[(msr -
                             MSR_MTRRphysBase(0)) / 2].base;
        break;
    case MSR_MTRRphysMask(0):
    case MSR_MTRRphysMask(1):
    case MSR_MTRRphysMask(2):
    case MSR_MTRRphysMask(3):
    case MSR_MTRRphysMask(4):
    case MSR_MTRRphysMask(5):
    case MSR_MTRRphysMask(6):
    case MSR_MTRRphysMask(7):
        val = env->mtrr_var[(msr -
                             MSR_MTRRphysMask(0)) / 2].mask;
        break;
    case MSR_MTRRfix64K_00000:
        val = env->mtrr_fixed[0];
        break;
    case MSR_MTRRfix16K_80000:
    case MSR_MTRRfix16K_A0000:
        val = env->mtrr_fixed[msr -
                              MSR_MTRRfix16K_80000 + 1];
        break;
    case MSR_MTRRfix4K_C0000:
    case MSR_MTRRfix4K_C8000:
    case MSR_MTRRfix4K_D0000:
    case MSR_MTRRfix4K_D8000:
    case MSR_MTRRfix4K_E0000:
    case MSR_MTRRfix4K_E8000:
    case MSR_MTRRfix4K_F0000:
    case MSR_MTRRfix4K_F8000:
        val = env->mtrr_fixed[msr -
                              MSR_MTRRfix4K_C0000 + 3];
        break;
    case MSR_MTRRdefType:
        val = env->mtrr_deftype;
        break;
    case MSR_MTRRcap:
        if (env->features[FEAT_1_EDX] & CPUID_MTRR) {
            val = MSR_MTRRcap_VCNT | MSR_MTRRcap_FIXRANGE_SUPPORT |
                MSR_MTRRcap_WC_SUPPORTED;
        } else {
            /* XXX: exception? */
            val = 0;
        }
        break;
    case MSR_P5_MC_ADDR:
    case MSR_P5_MC_TYPE:
        val = 0;
        break;
    case MSR_MCG_CAP:
        val = env->mcg_cap;
        break;
    case MSR_MCG_CTL:
        if (env->mcg_cap & MCG_CTL_P) {
            val = env->mcg_ctl;
        } else {
            val = 0;
        }
        break;
    case MSR_MCG_STATUS:
        val = env->mcg_status;
        break;
    case MSR_IA32_TSC:
        val = x86_tsc_read(env);
        break;
    case MSR_TSC_ADJUST:
        if (!(env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_TSC_ADJUST)) {
            return false;
        }
        val = env->tsc_adjust;
        break;
    case MSR_IA32_TSCDEADLINE: {
        BQL_LOCK_GUARD();

        if (!(env->features[FEAT_1_ECX] & CPUID_EXT_TSC_DEADLINE_TIMER)) {
            return false;
        }
        val = apic_get_tsc_deadline(x86_cpu->apic_state);
        break;
    }
    case MSR_AMD64_TSC_RATIO:
        if (!tsc_ratio_present(env)) {
            return false;
        }
        val = env->amd_tsc_scale_msr;
        break;
    case MSR_AMD64_AVIC_DOORBELL:
        /* Write-only. */
        return false;
    case MSR_IA32_MISC_ENABLE:
        val = env->msr_ia32_misc_enable;
        break;
    case MSR_IA32_DEBUGCTL:
        val = env->debugctl;
        break;
    case MSR_LASTBRANCH_FROM_IP:
        val = env->lbr_from;
        break;
    case MSR_LASTBRANCH_TO_IP:
        val = env->lbr_to;
        break;
    case MSR_LASTINT_FROM_IP:
        val = env->lbr_int_from;
        break;
    case MSR_LASTINT_TO_IP:
        val = env->lbr_int_to;
        break;
    case MSR_IA32_BNDCFGS:
        val = env->msr_bndcfgs;
        break;
    case MSR_IA32_U_CET:
    case MSR_IA32_S_CET:
        if (!x86_has_shstk(env) && !x86_has_ibt(env)) {
            return false;
        }
        val = msr == MSR_IA32_U_CET ? env->u_cet : env->s_cet;
        break;
    case MSR_IA32_PL0_SSP:
    case MSR_IA32_PL1_SSP:
    case MSR_IA32_PL2_SSP:
    case MSR_IA32_PL3_SSP:
        if (!x86_has_pl_ssp(env, msr)) {
            return false;
        }
        val = *x86_pl_ssp(env, msr - MSR_IA32_PL0_SSP);
        break;
#ifdef TARGET_X86_64
    case MSR_IA32_INT_SSP_TAB:
        if (!x86_has_shstk(env)) {
            return false;
        }
        val = env->int_ssp_table;
        break;
#endif
    case MSR_IA32_XSS:
        if (!(env->features[FEAT_XSAVE] & CPUID_XSAVE_XSAVES)) {
            return false;
        }
        val = env->xss;
        break;
    case MSR_IA32_UMWAIT_CONTROL:
        if (!(env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_WAITPKG)) {
            return false;
        }
        val = env->umwait;
        break;
    case MSR_PLATFORM_INFO:
        /* Only bit 31, CPUID faulting, as Linux 7.3's KVM gives guests. */
        if (!IS_INTEL_CPU(env)) {
            return false;
        }
        val = MSR_PLATFORM_INFO_CPUID_FAULT;
        break;
    case MSR_MISC_FEATURES_ENABLES:
        if (!IS_INTEL_CPU(env)) {
            return false;
        }
        val = env->msr_misc_features_enables;
        break;
    case MSR_K7_HWCR:
        val = env->msr_hwcr;
        break;
    case MSR_AMD_CPUID_7_FEATURES ... MSR_AMD_CPUID_EXT_FEATURES: {
        int index = msr - MSR_AMD_CPUID_7_FEATURES;

        if (!IS_AMD_CPU(env)) {
            return false;
        }
        val = amd_cpuid_override_bits(env, index) &
              ~env->amd_cpuid_hidden[index];
        break;
    }
    case MSR_DR0_ADDR_MASK:
    case MSR_DR1_ADDR_MASK ... MSR_DR1_ADDR_MASK + 2: {
        int index = msr == MSR_DR0_ADDR_MASK ? 0 :
                    msr - MSR_DR1_ADDR_MASK + 1;

        if (!x86_dr_addr_mask_exists(env, index)) {
            return false;
        }
        val = env->dr_addr_mask[index];
        break;
    }
     case MSR_IA32_UCODE_REV:
        val = x86_cpu->ucode_rev;
        break;
    case MSR_CORE_THREAD_COUNT: {
        val = cpu_x86_get_msr_core_thread_count(x86_cpu);
        break;
    }
    case MSR_APIC_START ... MSR_APIC_END: {
        int ret;
        int index = msr - MSR_APIC_START;

        {
            BQL_LOCK_GUARD();

            ret = apic_msr_read(x86_cpu->apic_state, index, &val);
        }
        if (ret < 0) {
            return false;
        }

        break;
    }
    case MSR_IA32_FEATURE_CONTROL:
        if (!x86_feature_control_exists(env)) {
            return false;
        }
        val = env->msr_ia32_feature_control;
        break;
    case MSR_IA32_VMX_BASIC ... MSR_IA32_VMX_EXIT_CTLS2:
        if (!x86_vmx_read_msr(env, msr, &val)) {
            return false;
        }
        break;
    case MSR_IA32_SPEC_CTRL:
        if (!spec_ctrl_bits(env)) {
            return false;
        }
        val = env->spec_ctrl;
        break;
    case MSR_IA32_ARCH_CAPABILITIES:
        if (!(env->features[FEAT_7_0_EDX] & CPUID_7_0_EDX_ARCH_CAPABILITIES)) {
            return false;
        }
        val = env->features[FEAT_ARCH_CAPABILITIES];
        break;
    case MSR_IA32_XAPIC_DISABLE_STATUS:
        if (!(env->features[FEAT_7_0_EDX] & CPUID_7_0_EDX_ARCH_CAPABILITIES) ||
            !(env->features[FEAT_ARCH_CAPABILITIES] &
              MSR_ARCH_CAP_XAPIC_DISABLE_STATUS)) {
            return false;
        }
        val = env_archcpu(env)->x2apic_locked ? LEGACY_XAPIC_DISABLED : 0;
        break;
    case MSR_IA32_PRED_CMD:
    case MSR_IA32_FLUSH_CMD:
        /* Write-only (Intel SDM 325462-093 Vol. 4, Table 2-2). */
        return false;
    default:
        if (msr >= MSR_MC0_CTL
            && msr < MSR_MC0_CTL + 4 * 32) {
            uint32_t offset = msr - MSR_MC0_CTL;

            /* Banks past MCG_CAP.Count do not exist. */
            if (offset >= 4 * (env->mcg_cap & MCG_CAP_BANKS_MASK)) {
                return false;
            }
            val = env->mce_banks[offset];
            break;
        }
        /* XXX: exception? */
        val = 0;
        break;
    }
    *valp = val;
    return true;
}

void HELPER(rdmsr)(CPUX86State *env)
{
    uint64_t val;
    bool ok;

    cpu_svm_check_intercept_param(env, SVM_EXIT_MSR, 0, GETPC());

    if (unlikely(env->svm_x2avic) &&
        (uint32_t)env->regs[R_ECX] >= MSR_APIC_START &&
        (uint32_t)env->regs[R_ECX] <= MSR_APIC_END) {
        if (!svm_x2avic_rdmsr(env, env->regs[R_ECX], &val, GETPC())) {
            raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
        }
        env->regs[R_EAX] = (uint32_t)val;
        env->regs[R_EDX] = (uint32_t)(val >> 32);
        return;
    }
    if (unlikely(env->vmx.nonroot) &&
        x86_vmx_x2apic_rdmsr(env, env->regs[R_ECX], &val)) {
        env->regs[R_EAX] = (uint32_t)val;
        env->regs[R_EDX] = (uint32_t)(val >> 32);
        return;
    }

    /* RDMSR has not retired for the PMU it accesses. */
    env->pmu.unretired = 1;
    ok = x86_cpu_rdmsr(env, (uint32_t)env->regs[R_ECX], &val);
    env->pmu.unretired = 0;
    if (!ok) {
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
    }
    env->regs[R_EAX] = (uint32_t)(val);
    env->regs[R_EDX] = (uint32_t)(val >> 32);
    if ((uint32_t)env->regs[R_ECX] == MSR_IA32_TSC) {
        x86_vmx_tsc_seen(env);
    }
}

/*
 * INVPCID: its SVM intercept comes before all its checks but CPL's (AMD64
 * Architecture Programmer's Manual Volume 2, 24593 rev. 3.45, Table 15-7),
 * with the descriptor's address in EXITINFO1 and the type in EXITINFO2,
 * where Linux 7.3's KVM reads them; then types above 3, descriptor bits
 * 63:12, PCIDs other than 0 for types 0 and 1 without CR4.PCIDE, and a
 * type 0 address that is not canonical for the processor raise #GP (Intel
 * SDM 325462-093 Vol. 2A, INVPCID). QEMU's TLB holds the current PCID's
 * translations only, so type 0 drops the page and the others drop all,
 * the global ones too, as the processor may.
 */
void HELPER(invpcid)(CPUX86State *env, target_ulong addr, target_ulong type)
{
    CPUState *cs = env_cpu(env);
    uintptr_t ra = GETPC();
    uint64_t desc, laddr;

    if (env->vmx.nonroot) {
        x86_vmx_invpcid(env, ra);
    }

    if (cpu_svm_has_intercept(env, SVM_EXIT_INVPCID)) {
        x86_stq_phys(cs, env->vm_vmcb +
                     offsetof(struct vmcb, control.exit_info_2), type);
        cpu_vmexit(env, SVM_EXIT_INVPCID, addr, ra);
    }
    if (type > 3) {
        raise_exception_ra(env, EXCP0D_GPF, ra);
    }
    desc = cpu_ldq_le_data_ra(env, addr, ra);
    laddr = cpu_ldq_le_data_ra(env, addr + 8, ra);
    if ((desc >> 12) ||
        (type <= 1 && (desc & 0xfff) && !(env->cr[4] & CR4_PCIDE_MASK)) ||
        (type == 0 && !x86_canonical(env, laddr, false))) {
        raise_exception_ra(env, EXCP0D_GPF, ra);
    }
    if (type == 0) {
        tlb_flush_page_by_mmuidx(cs, laddr, x86_mmu_context_map(env));
    } else {
        tlb_flush_by_mmuidx(cs, x86_mmu_context_map(env));
    }
}

/* INVLPG drops the page from the current ASID's translations only. */
void HELPER(flush_page)(CPUX86State *env, target_ulong addr)
{
    tlb_flush_page_by_mmuidx(env_cpu(env), addr, x86_mmu_context_map(env));
}

/*
 * INVLPGA drops the page from the translations of the ASID that ECX gives,
 * the host's or the guest's ones kept, but no nested translation (AMD64
 * Architecture Programmer's Manual Volume 2, 24593 rev. 3.45, 15.16.2). A
 * guest that runs it itself drops the page from all of them.
 */
void HELPER(invlpga)(CPUX86State *env, target_ulong addr, uint32_t asid)
{
    CPUState *cs = env_cpu(env);

    if (env->hflags & HF_GUEST_MASK) {
        tlb_flush_page(cs, addr);
    } else if (asid == 0) {
        tlb_flush_page_by_mmuidx(cs, addr, MMU_HOST_IDX_MAP);
    } else if (asid == env->svm_tlb_asid) {
        tlb_flush_page_by_mmuidx(cs, addr, MMU_GUEST_IDX_MAP);
    }
}

/* INVLPGB's attributes in rAX, those it compares and those it allows. */
#define INVLPGB_VA              (1 << 0)
#define INVLPGB_ASID            (1 << 2)
#define INVLPGB_NESTED          (1 << 5)
#define INVLPGB_RESERVED        0xfc0

/*
 * INVLPGB: its SVM intercept comes before all its checks but CPL's, then
 * #UD where the hypervisor has not enabled it in guest mode, and the
 * intercept of illegal ones before their #GP (AMD64 Architecture
 * Programmer's Manual Volume 2, 24593 rev. 3.45, Tables 15-7 and B-1;
 * Volume 3, 24594 rev. 3.38, INVLPGB). Without the IOMMU's invalidations
 * (EnhancedTlbi), rAX[6] is reserved. It drops, on every processor, the
 * translations of the address range, PCID, and ASID it selects, a guest's
 * of its own ASID, and the nested ones with rAX[5]. QEMU's TLB holds the
 * current PCID's translations only, and guest mode's MMU indexes those of
 * one ASID, so a PCID drops the whole range and any ASID but the host's
 * drops the range from every processor's guest translations, as INVLPGB
 * may. All of it is done when INVLPGB ends, before the next instruction.
 */
void HELPER(invlpgb)(CPUX86State *env, target_ulong rax)
{
    CPUState *cs = env_cpu(env);
    uintptr_t ra = GETPC();
    uint32_t ecx = env->regs[R_ECX];
    uint32_t edx = env->regs[R_EDX];
    uint32_t asid = edx & 0xffff;
    bool guest = env->hflags & HF_GUEST_MASK;
    MMUIdxMap idxmap;

    if (cpu_svm_has_intercept(env, SVM_EXIT_INVLPGB)) {
        cpu_vmexit(env, SVM_EXIT_INVLPGB, 0, ra);
    }
    if (guest && !env->svm_tlbi_enabled) {
        raise_exception_ra(env, EXCP06_ILLOP, ra);
    }
    if ((rax & INVLPGB_RESERVED) ||
        ((rax & INVLPGB_NESTED) &&
         !(env->features[FEAT_8000_0008_EBX] &
           CPUID_8000_0008_EBX_INVLPGB_NESTED)) ||
        (edx >> 28) ||
        ((edx >> 16) && !(env->cr[4] & CR4_PCIDE_MASK)) ||
        (asid && !(env->efer & MSR_EFER_SVME)) ||
        asid > SVM_NR_ASIDS ||
        (ecx & 0xffff) > INVLPGB_COUNT_MAX ||
        ((env->cr[0] & CR0_PG_MASK) &&
         (env->cr[4] & (CR4_PAE_MASK | CR4_PSE_MASK)) == CR4_PSE_MASK)) {
        if (cpu_svm_has_intercept(env, SVM_EXIT_INVLPGB_ILLEGAL)) {
            cpu_vmexit(env, SVM_EXIT_INVLPGB_ILLEGAL, 0, ra);
        }
        raise_exception_ra(env, EXCP0D_GPF, ra);
    }

    if (guest || ((rax & INVLPGB_ASID) && asid)) {
        idxmap = MMU_GUEST_IDX_MAP;
    } else if (rax & INVLPGB_ASID) {
        idxmap = MMU_HOST_IDX_MAP;
    } else {
        idxmap = MMU_HOST_IDX_MAP | MMU_GUEST_IDX_MAP;
    }
    if (rax & INVLPGB_VA) {
        vaddr stride = ecx >> 31 ? 2 * MiB : 4 * KiB;

        tlb_flush_range_by_mmuidx_all_cpus_synced(cs, rax & TARGET_PAGE_MASK,
                                                  ((ecx & 0xffff) + 1) *
                                                  stride, idxmap,
                                                  TARGET_LONG_BITS);
    } else {
        tlb_flush_by_mmuidx_all_cpus_synced(cs, idxmap);
    }
    if (rax & INVLPGB_NESTED) {
        tlb_flush_by_mmuidx_all_cpus_synced(cs, 1 << MMU_NESTED_IDX |
                                                1 << MMU_NESTED_SUP_IDX);
    }
}

/*
 * TLBSYNC: #UD where the hypervisor has not enabled it in guest mode, then
 * the SVM intercept that TlbiCtl brings (AMD64 Architecture Programmer's
 * Manual Volume 2, 24593 rev. 3.45, Tables 15-7 and B-1). It has nothing
 * to wait for: each INVLPGB is done when it ends.
 */
void HELPER(tlbsync)(CPUX86State *env)
{
    uintptr_t ra = GETPC();

    if ((env->hflags & HF_GUEST_MASK) && !env->svm_tlbi_enabled) {
        raise_exception_ra(env, EXCP06_ILLOP, ra);
    }
    if ((env->features[FEAT_SVM] & CPUID_SVM_TLBICTL) &&
        cpu_svm_has_intercept(env, SVM_EXIT_TLBSYNC)) {
        cpu_vmexit(env, SVM_EXIT_TLBSYNC, 0, ra);
    }
}

static G_NORETURN void do_hlt(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);

    do_end_instruction(env);
    cs->halted = 1;
    cs->exception_index = EXCP_HLT;
    cpu_loop_exit(cs);
}

G_NORETURN void HELPER(hlt)(CPUX86State *env)
{
    /*
     * The idle HLT intercept takes a HLT only where no virtual interrupt or
     * virtual NMI is pending (AMD64 Architecture Programmer's Manual Volume
     * 2, 24593 rev. 3.45, 15.9).
     */
    if ((env->hflags & HF_GUEST_MASK) && !(env->int_ctl & V_IRQ_MASK) &&
        !(svm_vnmi_enabled(env) && (env->int_ctl & V_NMI_PENDING_MASK))) {
        cpu_svm_check_intercept_param(env, SVM_EXIT_IDLE_HLT, 0, GETPC());
    }
    /*
     * Under VMX's monitor trap flag, the MTF VM exit comes from the HLT
     * state (Intel SDM 325462-093 Vol. 3C, 28.5.2).
     */
    if (x86_vmx_mtf(env)) {
        do_end_instruction(env);
        env->vmx.exit_hlt = true;
        x86_vmx_mtf_step(env, x86_step_trap(env, false));
    }
    /* The #DB MOV SS or POP SS held comes after the HLT, which ends. */
    if (env->db_movss) {
        do_end_instruction(env);
        raise_debug_exception(env, 0, 0);
    }
    do_hlt(env);
}

void HELPER(monitor)(CPUX86State *env, target_ulong ptr)
{
    if ((uint32_t)env->regs[R_ECX] != 0) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }
    /* XXX: store address? */
    cpu_svm_check_intercept_param(env, SVM_EXIT_MONITOR, 0, GETPC());
    env->monitor_armed = true;
    /*
     * UMWAIT does not wait after a MONITOR (Intel SDM 325462-093 Vol. 2B,
     * UMWAIT).
     */
    env->umonitor_armed = false;
}

G_NORETURN void HELPER(mwait)(CPUX86State *env, int next_eip_addend)
{
    CPUState *cs = env_cpu(env);

    if ((uint32_t)env->regs[R_ECX] != 0) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }
    cpu_svm_check_intercept_param(env, SVM_EXIT_MWAIT, 0, GETPC());
    env->eip += next_eip_addend;

    /*
     * Without monitoring armed, MWAIT continues at once (Intel SDM
     * 325462-093 Vol. 2B, MWAIT); so it does under VMX's monitor trap
     * flag, as any event may end its wait, here the MTF VM exit.
     */
    if (!env->monitor_armed || x86_vmx_mtf(env)) {
        do_end_instruction(env);
        HELPER(rechecking_single_step)(env);
        cpu_loop_exit(cs);
    }
    env->monitor_armed = false;
    /* XXX: not complete but not completely erroneous */
    if (cs->cpu_index != 0 || CPU_NEXT(cs) != NULL) {
        HELPER(pause)(env);
    } else {
        do_hlt(env);
    }
}

/*
 * UMONITOR arms address-range monitoring of the line holding ADDR, with the
 * faults and accessed flag of a byte load (Intel SDM 325462-093 Vol. 2B,
 * UMONITOR), where VMX non-root operation has "enable user wait and pause"
 * (Intel SDM 325462-093 Vol. 3C, 28.3). On memory, a store shows as a change
 * of the line's bytes.
 */
void HELPER(umonitor)(CPUX86State *env, target_ulong addr)
{
    CPUState *cs = env_cpu(env);
    CPUTLBEntryFull *full;
    void *host;

    if (env->vmx.nonroot && !x86_vmx_user_wait_enabled(env)) {
        raise_exception_ra(env, EXCP06_ILLOP, GETPC());
    }
    probe_access_full(env, addr, 1, MMU_DATA_LOAD, cpu_mmu_index(cs, false),
                      false, &host, &full, GETPC());
    env->monitor_armed = false;
    env->umonitor_armed = true;
    env->umonitor_line = full->phys_addr | (addr & 0xfc0);
    env->umonitor_attrs = full->attrs;
    env->umonitor_memory =
        host && address_space_read(cpu_addressspace(cs, full->attrs),
                                   env->umonitor_line, full->attrs,
                                   env->umonitor_bytes,
                                   sizeof(env->umonitor_bytes)) == MEMTX_OK;
}

/* How often an UMWAIT looks for a store to UMONITOR's line. */
#define USER_WAIT_POLL_NS 20000

/* Whether a store changed the bytes of UMONITOR's line since it armed. */
static bool umonitor_stored(CPUX86State *env)
{
    AddressSpace *as = cpu_addressspace(env_cpu(env), env->umonitor_attrs);
    uint8_t bytes[sizeof(env->umonitor_bytes)];

    if (!env->umonitor_memory) {
        return false;
    }
    return address_space_read(as, env->umonitor_line, env->umonitor_attrs,
                              bytes, sizeof(bytes)) != MEMTX_OK ||
           memcmp(bytes, env->umonitor_bytes, sizeof(bytes));
}

/* Has the wait's timer fire at its deadline, or at UMWAIT's next look. */
static void user_wait_arm(CPUX86State *env)
{
    uint64_t now = x86_tsc_read(env);
    uint64_t delay = env->user_wait_deadline - now;
    int64_t ns = 0;

    if (now < env->user_wait_deadline) {
        if (env->vmx.nonroot) {
            delay = x86_vmx_tsc_delay(env, delay);
        }
        ns = cpu_tsc_ticks_ns(env, delay);
    }
    if (env->user_wait_umwait) {
        ns = MIN(ns, USER_WAIT_POLL_NS);
    }
    timer_mod(env_archcpu(env)->user_wait_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + ns);
}

/* The deadline or a store to UMWAIT's line ends the wait; else arm again. */
static void user_wait_cb(void *opaque)
{
    X86CPU *cpu = opaque;
    CPUX86State *env = &cpu->env;

    if (!env->user_wait) {
        return;
    }
    if (x86_tsc_read(env) < env->user_wait_deadline &&
        !(env->user_wait_umwait && umonitor_stored(env))) {
        user_wait_arm(env);
        return;
    }
    qatomic_set(&env->user_wait_over, true);
    qemu_cpu_kick(CPU(cpu));
}

void x86_user_wait_init(X86CPU *cpu)
{
    cpu->user_wait_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, user_wait_cb, cpu);
}

/*
 * Ends a wait, with CF set where IA32_UMWAIT_CONTROL's limit ended it: in
 * CC_SRC within the execution loop, else in EFLAGS, as a halted processor
 * leaves the loop.
 */
void x86_user_wait_end(CPUX86State *env)
{
    env->user_wait = false;
    timer_del(env_archcpu(env)->user_wait_timer);
    if (env->user_wait_limited &&
        x86_tsc_read(env) >= env->user_wait_deadline) {
        if (env_archcpu(env)->eflags_in_tcg) {
            env->cc_src |= CC_C;
        } else {
            env->eflags |= CC_C;
        }
    }
}

/*
 * UMWAIT and TPAUSE wait until the TSC that RDTSC reads reaches EDX:EAX, or
 * for at most IA32_UMWAIT_CONTROL[31:2] << 2 ticks, which then sets CF; AF,
 * PF, SF, ZF, and OF end clear. UMWAIT waits only with UMONITOR's monitoring
 * armed, and a store to its line ends the wait (Intel SDM 325462-093 Vol.
 * 2B, UMWAIT and TPAUSE). VMX non-root operation needs "enable user wait and
 * pause", and exits with "RDTSC exiting" (Intel SDM 325462-093 Vol. 3C,
 * 28.1.3 and 28.3): before the #GP of a reserved source bit, as on Intel
 * processors.
 */
G_NORETURN void HELPER(user_wait)(CPUX86State *env, target_ulong src,
                                  uint32_t info, int next_eip_addend)
{
    CPUState *cs = env_cpu(env);
    bool umwait = info & USER_WAIT_UMWAIT;
    uint64_t deadline = (uint64_t)(uint32_t)env->regs[R_EDX] << 32 |
                        (uint32_t)env->regs[R_EAX];
    uint64_t limit = env->umwait & 0xfffffffc;
    uint64_t now;

    if (env->vmx.nonroot && !x86_vmx_user_wait_enabled(env)) {
        raise_exception_ra(env, EXCP06_ILLOP, GETPC());
    }
    if ((env->cr[4] & CR4_TSD_MASK) && (env->hflags & HF_CPL_MASK)) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }
    if (env->vmx.nonroot) {
        x86_vmx_user_wait_exit(env,
                               umwait ? VMX_EXIT_UMWAIT : VMX_EXIT_TPAUSE,
                               (info & USER_WAIT_REG) << 3, GETPC());
    }
    if ((uint32_t)src & ~1u) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }

    env->eip += next_eip_addend;
    CC_SRC = cpu_cc_compute_all(env) &
             ~(CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
    CC_OP = CC_OP_EFLAGS;
    now = x86_tsc_read(env);
    env->user_wait_umwait = umwait;
    env->user_wait_limited = limit && now + limit < deadline;
    env->user_wait_deadline = env->user_wait_limited ? now + limit : deadline;
    /* A store since UMONITOR, this processor's too, triggered it. */
    if (umwait && env->umonitor_armed && umonitor_stored(env)) {
        env->umonitor_armed = false;
    }
    /*
     * As MWAIT, the wait ends at once under VMX's monitor trap flag, with
     * the MTF VM exit as the event that ends it.
     */
    if (now >= env->user_wait_deadline || x86_vmx_mtf(env) ||
        (umwait && !env->umonitor_armed)) {
        x86_user_wait_end(env);
        do_end_instruction(env);
        HELPER(rechecking_single_step)(env);
        cpu_loop_exit(cs);
    }
    if (umwait) {
        env->umonitor_armed = false;
    }
    env->user_wait = true;
    qatomic_set(&env->user_wait_over, false);
    user_wait_arm(env);
    do_hlt(env);
}
