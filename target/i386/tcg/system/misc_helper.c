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
#include "cpu.h"
#include "exec/helper-proto.h"
#include "accel/tcg/cpu-ldst.h"
#include "accel/tcg/cpu-loop.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "exec/cputlb.h"
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
 * without PE, NW without CD, clearing PG in 64-bit mode, and turning on
 * IA-32e mode without PAE, from code with CS.L, or with a 16-bit TSS in TR
 * (Intel SDM 325462-093 Vol. 2B, MOV, Move to/from Control Registers; AMD64
 * Architecture Programmer's Manual Volume 3, 24594 rev. 3.38, MOV CRn).
 * The reserved bits of CR0[31:0] are ignored.
 */
static bool cr0_valid(CPUX86State *env, uint64_t cr0)
{
    if ((cr0 >> 32) ||
        ((cr0 & CR0_PG_MASK) && !(cr0 & CR0_PE_MASK)) ||
        ((cr0 & CR0_NW_MASK) && !(cr0 & CR0_CD_MASK))) {
        return false;
    }
#ifdef TARGET_X86_64
    if ((env->hflags & HF_CS64_MASK) && !(cr0 & CR0_PG_MASK)) {
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
 * those of absent features, a change of LA57 or clearing PAE in IA-32e mode
 * (the same documents).
 */
static bool cr4_valid(CPUX86State *env, uint64_t cr4)
{
    if (cr4 & cr4_reserved_bits(env)) {
        return false;
    }
    if ((env->efer & MSR_EFER_LMA) &&
        (((cr4 ^ env->cr[4]) & CR4_LA57_MASK) || !(cr4 & CR4_PAE_MASK))) {
        return false;
    }
    return true;
}

void HELPER(write_crN)(CPUX86State *env, int reg, target_ulong t0)
{
    switch (reg) {
    case 0:
        if (!cr0_valid(env, t0)) {
            raise_exception_ra(env, EXCP0D_GPF, GETPC());
        }
        t0 &= CR0_DEFINED_MASK;
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
        cpu_x86_update_cr0(env, t0);
        break;
    case 3:
        if ((env->efer & MSR_EFER_LMA) &&
                (t0 & ((~0ULL) << env_archcpu(env)->phys_bits))) {
            raise_exception_ra(env, EXCP0D_GPF, GETPC());
        }
        if (!(env->efer & MSR_EFER_LMA)) {
            t0 &= 0xffffffffUL;
        }
        cpu_x86_update_cr3(env, t0);
        break;
    case 4:
        if (!cr4_valid(env, t0)) {
            raise_exception_ra(env, EXCP0D_GPF, GETPC());
        }
        cpu_x86_update_cr4(env, t0);
        break;
    case 8:
        if (t0 & ~(target_ulong)0xf) {
            raise_exception_ra(env, EXCP0D_GPF, GETPC());
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
        env->cr[reg] = t0;
        break;
    }
}

/* The TSC Ratio MSR exists where CPUID Fn8000_000A_EDX shows TscRateMsr. */
static bool tsc_ratio_present(CPUX86State *env)
{
    return (env->features[FEAT_8000_0001_ECX] & CPUID_EXT3_SVM) &&
           (env->features[FEAT_SVM] & CPUID_SVM_TSCSCALE);
}

void HELPER(wrmsr)(CPUX86State *env)
{
    uint64_t val;
    CPUState *cs = env_cpu(env);

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

    switch ((uint32_t)env->regs[R_ECX]) {
    case MSR_IA32_SYSENTER_CS:
        env->sysenter_cs = val & 0xffff;
        break;
    case MSR_IA32_SYSENTER_ESP:
        env->sysenter_esp = val;
        break;
    case MSR_IA32_SYSENTER_EIP:
        env->sysenter_eip = val;
        break;
    case MSR_IA32_APICBASE: {
        int ret;

        if (val & MSR_IA32_APICBASE_RESERVED) {
            goto error;
        }

        ret = cpu_set_apic_base(env_archcpu(env)->apic_state, val);
        if (ret < 0) {
            goto error;
        }
        break;
    }
    case MSR_EFER:
        {
            uint64_t update_mask;

            update_mask = 0;
            if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_SYSCALL) {
                update_mask |= MSR_EFER_SCE;
            }
            if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM) {
                update_mask |= MSR_EFER_LME;
            }
            if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_FFXSR) {
                update_mask |= MSR_EFER_FFXSR;
            }
            if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_NX) {
                update_mask |= MSR_EFER_NXE;
            }
            if (env->features[FEAT_8000_0001_ECX] & CPUID_EXT3_SVM) {
                update_mask |= MSR_EFER_SVME;
            }
            if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_FFXSR) {
                update_mask |= MSR_EFER_FFXSR;
            }
            cpu_load_efer(env, (env->efer & ~update_mask) |
                          (val & update_mask));
        }
        break;
    case MSR_STAR:
        env->star = val;
        break;
    case MSR_PAT:
        env->pat = val;
        break;
    case MSR_IA32_PKRS:
        if (val & 0xFFFFFFFF00000000ull) {
            goto error;
        }
        env->pkrs = val;
        tlb_flush(cs);
        break;
    case MSR_VM_HSAVE_PA:
        if (val & (0xfff | ((~0ULL) << env_archcpu(env)->phys_bits))) {
            goto error;
        }
        env->vm_hsave = val;
        break;
#ifdef TARGET_X86_64
    case MSR_LSTAR:
        env->lstar = val;
        break;
    case MSR_CSTAR:
        env->cstar = val;
        break;
    case MSR_FMASK:
        env->fmask = val;
        break;
    case MSR_FSBASE:
        env->segs[R_FS].base = val;
        break;
    case MSR_GSBASE:
        env->segs[R_GS].base = val;
        break;
    case MSR_KERNELGSBASE:
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
        env->mtrr_var[((uint32_t)env->regs[R_ECX] -
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
        env->mtrr_var[((uint32_t)env->regs[R_ECX] -
                       MSR_MTRRphysMask(0)) / 2].mask = val;
        break;
    case MSR_MTRRfix64K_00000:
        env->mtrr_fixed[(uint32_t)env->regs[R_ECX] -
                        MSR_MTRRfix64K_00000] = val;
        break;
    case MSR_MTRRfix16K_80000:
    case MSR_MTRRfix16K_A0000:
        env->mtrr_fixed[(uint32_t)env->regs[R_ECX] -
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
        env->mtrr_fixed[(uint32_t)env->regs[R_ECX] -
                        MSR_MTRRfix4K_C0000 + 3] = val;
        break;
    case MSR_MTRRdefType:
        env->mtrr_deftype = val;
        break;
    case MSR_MCG_STATUS:
        env->mcg_status = val;
        break;
    case MSR_MCG_CTL:
        if ((env->mcg_cap & MCG_CTL_P)
            && (val == 0 || val == ~(uint64_t)0)) {
            env->mcg_ctl = val;
        }
        break;
    case MSR_IA32_TSC:
        /* The counter takes the value written, not scaled or offset. */
        env->tsc_written_delta = val - cpu_get_tsc(env);
        break;
    case MSR_TSC_AUX:
        env->tsc_aux = val;
        break;
    case MSR_AMD64_TSC_RATIO:
        if (!tsc_ratio_present(env) || (val & MSR_AMD64_TSC_RATIO_RESERVED)) {
            goto error;
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
            goto error;
        }
        svm_avic_doorbell(env, val);
        break;
    case MSR_IA32_MISC_ENABLE:
        env->msr_ia32_misc_enable = val;
        break;
    case MSR_IA32_DEBUGCTL:
        if (val & ~(DEBUGCTL_LBR | DEBUGCTL_BTF)) {
            goto error;
        }
        env->debugctl = val;
        break;
    case MSR_LASTBRANCH_FROM_IP ... MSR_LASTINT_TO_IP:
        /* Read-only. */
        goto error;
    case MSR_IA32_BNDCFGS:
        /* FIXME: #GP if reserved bits are set.  */
        /* FIXME: Extend highest implemented bit of linear address.  */
        env->msr_bndcfgs = val;
        cpu_sync_bndcs_hflags(env);
        break;
    case MSR_APIC_START ... MSR_APIC_END: {
        int ret;
        int index = (uint32_t)env->regs[R_ECX] - MSR_APIC_START;

        bql_lock();
        ret = apic_msr_write(env_archcpu(env)->apic_state, index, val);
        bql_unlock();
        if (ret < 0) {
            goto error;
        }

        break;
    }
    default:
        if ((uint32_t)env->regs[R_ECX] >= MSR_MC0_CTL
            && (uint32_t)env->regs[R_ECX] < MSR_MC0_CTL +
            (4 * env->mcg_cap & 0xff)) {
            uint32_t offset = (uint32_t)env->regs[R_ECX] - MSR_MC0_CTL;
            if ((offset & 0x3) != 0
                || (val == 0 || val == ~(uint64_t)0)) {
                env->mce_banks[offset] = val;
            }
            break;
        }
        /* XXX: exception? */
        break;
    }
    return;
error:
    raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
}

void HELPER(rdmsr)(CPUX86State *env)
{
    X86CPU *x86_cpu = env_archcpu(env);
    uint64_t val;

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

    switch ((uint32_t)env->regs[R_ECX]) {
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
        val = env->mtrr_var[((uint32_t)env->regs[R_ECX] -
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
        val = env->mtrr_var[((uint32_t)env->regs[R_ECX] -
                             MSR_MTRRphysMask(0)) / 2].mask;
        break;
    case MSR_MTRRfix64K_00000:
        val = env->mtrr_fixed[0];
        break;
    case MSR_MTRRfix16K_80000:
    case MSR_MTRRfix16K_A0000:
        val = env->mtrr_fixed[(uint32_t)env->regs[R_ECX] -
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
        val = env->mtrr_fixed[(uint32_t)env->regs[R_ECX] -
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
    case MSR_AMD64_TSC_RATIO:
        if (!tsc_ratio_present(env)) {
            raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
        }
        val = env->amd_tsc_scale_msr;
        break;
    case MSR_AMD64_AVIC_DOORBELL:
        /* Write-only. */
        raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
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
     case MSR_IA32_UCODE_REV:
        val = x86_cpu->ucode_rev;
        break;
    case MSR_CORE_THREAD_COUNT: {
        val = cpu_x86_get_msr_core_thread_count(x86_cpu);
        break;
    }
    case MSR_APIC_START ... MSR_APIC_END: {
        int ret;
        int index = (uint32_t)env->regs[R_ECX] - MSR_APIC_START;

        bql_lock();
        ret = apic_msr_read(x86_cpu->apic_state, index, &val);
        bql_unlock();
        if (ret < 0) {
            raise_exception_err_ra(env, EXCP0D_GPF, 0, GETPC());
        }

        break;
    }
    default:
        if ((uint32_t)env->regs[R_ECX] >= MSR_MC0_CTL
            && (uint32_t)env->regs[R_ECX] < MSR_MC0_CTL +
            (4 * env->mcg_cap & 0xff)) {
            uint32_t offset = (uint32_t)env->regs[R_ECX] - MSR_MC0_CTL;
            val = env->mce_banks[offset];
            break;
        }
        /* XXX: exception? */
        val = 0;
        break;
    }
    env->regs[R_EAX] = (uint32_t)(val);
    env->regs[R_EDX] = (uint32_t)(val >> 32);
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
    do_hlt(env);
}

void HELPER(monitor)(CPUX86State *env, target_ulong ptr)
{
    if ((uint32_t)env->regs[R_ECX] != 0) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }
    /* XXX: store address? */
    cpu_svm_check_intercept_param(env, SVM_EXIT_MONITOR, 0, GETPC());
}

G_NORETURN void HELPER(mwait)(CPUX86State *env, int next_eip_addend)
{
    CPUState *cs = env_cpu(env);

    if ((uint32_t)env->regs[R_ECX] != 0) {
        raise_exception_ra(env, EXCP0D_GPF, GETPC());
    }
    cpu_svm_check_intercept_param(env, SVM_EXIT_MWAIT, 0, GETPC());
    env->eip += next_eip_addend;

    /* XXX: not complete but not completely erroneous */
    if (cs->cpu_index != 0 || CPU_NEXT(cs) != NULL) {
        HELPER(pause)(env);
    } else {
        do_hlt(env);
    }
}
