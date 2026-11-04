/*
 *  x86 SVM AVIC, the advanced virtual interrupt controller (system only)
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
#include "qemu/bswap.h"
#include "qemu/host-utils.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "exec/target_page.h"
#include "system/memory.h"
#include "accel/tcg/cpu-loop.h"
#include "tcg/helper-tcg.h"

/*
 * The offsets in the vAPIC backing page of the registers AVIC treats
 * specially (AMD64 Architecture Programmer's Manual Volume 2, 24593 rev.
 * 3.45, 15.29.3.1, Table 15-22).
 */
#define AVIC_ID         0x20
#define AVIC_VERSION    0x30
#define AVIC_TPR        0x80
#define AVIC_APR        0x90
#define AVIC_PPR        0xa0
#define AVIC_EOI        0xb0
#define AVIC_RRD        0xc0
#define AVIC_LDR        0xd0
#define AVIC_DFR        0xe0
#define AVIC_SVR        0xf0
#define AVIC_ISR        0x100
#define AVIC_TMR        0x180
#define AVIC_IRR        0x200
#define AVIC_ESR        0x280
#define AVIC_CMCI       0x2f0
#define AVIC_ICRL       0x300
#define AVIC_ICRH       0x310
#define AVIC_LVT_TIMER  0x320
#define AVIC_LVT_ERROR  0x370
#define AVIC_TMICT      0x380
#define AVIC_TMCCT      0x390
#define AVIC_TDCR       0x3e0
#define AVIC_SELF_IPI   0x3f0
#define AVIC_EXT_FEAT   0x400
#define AVIC_EXT_CTRL   0x410
#define AVIC_SEOI       0x420
#define AVIC_IER        0x480
#define AVIC_EILVT      0x500
#define AVIC_RESERVED   0x580

/* Physical and logical APIC ID table entries (Tables 15-23 and 15-24). */
#define AVIC_PHYS_VALID     (1ULL << 63)
#define AVIC_PHYS_RUNNING   (1ULL << 62)
#define AVIC_PHYS_BACKING   MAKE_64BIT_MASK(12, 40)
#define AVIC_PHYS_HOST_ID   0xfff
#define AVIC_LOGICAL_VALID  (1u << 31)

/* The causes AVIC_INCOMPLETE_IPI gives in EXITINFO2[63:32] (Table 15-27). */
#define AVIC_IPI_BAD_TYPE       0
#define AVIC_IPI_NOT_RUNNING    1
#define AVIC_IPI_BAD_TARGET     2
#define AVIC_IPI_BAD_VECTOR     4

/* What AVIC does with a guest access to a vAPIC register (Table 15-22). */
typedef enum AVICAction {
    AVIC_ALLOW,
    AVIC_FAULT,
    AVIC_TRAP,
    AVIC_ACCEL_TPR,
    AVIC_ACCEL_EOI,
    AVIC_ACCEL_ICR,
} AVICAction;

static AVICAction avic_action(unsigned int reg, bool write)
{
    if (reg >= AVIC_RESERVED) {
        return AVIC_FAULT;
    }
    switch (reg) {
    case AVIC_ID:
    case AVIC_RRD ... AVIC_SVR:
    case AVIC_ESR:
    case AVIC_LVT_TIMER ... AVIC_TMICT:
    case AVIC_TDCR:
        return write ? AVIC_TRAP : AVIC_ALLOW;
    case AVIC_VERSION:
    case AVIC_PPR:
    case AVIC_ISR ... AVIC_IRR + 0x70:
        return write ? AVIC_FAULT : AVIC_ALLOW;
    case AVIC_APR:
    case AVIC_TMCCT:
    case AVIC_EXT_FEAT ... AVIC_SEOI:
    case AVIC_IER ... AVIC_IER + 0x70:
    /* Without ExtLvtAvicAccessChg, the extended LVTs fault. */
    case AVIC_EILVT ... AVIC_EILVT + 0x70:
        return AVIC_FAULT;
    case AVIC_TPR:
        return write ? AVIC_ACCEL_TPR : AVIC_ALLOW;
    case AVIC_EOI:
        return write ? AVIC_ACCEL_EOI : AVIC_ALLOW;
    case AVIC_ICRL:
        return write ? AVIC_ACCEL_ICR : AVIC_ALLOW;
    default:
        return AVIC_ALLOW;
    }
}

static uint32_t avic_get(CPUX86State *env, unsigned int reg)
{
    return x86_ldl_phys(env_cpu(env), env->svm_avic_backing + reg);
}

static void avic_set(CPUX86State *env, unsigned int reg, uint32_t val)
{
    x86_stl_phys(env_cpu(env), env->svm_avic_backing + reg, val);
}

/* The highest vector of the 256-bit register at REG, -1 for none. */
static int avic_highest(CPUX86State *env, unsigned int reg)
{
    for (int i = 7; i >= 0; i--) {
        uint32_t word = avic_get(env, reg + i * 0x10);

        if (word) {
            return i * 32 + 31 - clz32(word);
        }
    }
    return -1;
}

static bool avic_vector_set(CPUX86State *env, unsigned int reg, int vector)
{
    return avic_get(env, reg + vector / 32 * 0x10) & (1u << (vector % 32));
}

/* PPR, from TPR and the highest vector in service, kept in the page. */
static uint32_t avic_update_ppr(CPUX86State *env)
{
    uint32_t tpr = avic_get(env, AVIC_TPR) & 0xff;
    int isrv = avic_highest(env, AVIC_ISR);
    uint32_t ppr = tpr;

    if (isrv >= 0 && (isrv & 0xf0) > (tpr & 0xf0)) {
        ppr = isrv & 0xf0;
    }
    avic_set(env, AVIC_PPR, ppr);
    return ppr;
}

/*
 * Sets or clears bit VECTOR of the IRR of the backing page at PAGE, which
 * other processors set as well, atomically.
 */
static void avic_irr_update(CPUState *cs, hwaddr page, int vector, bool set)
{
    hwaddr len = 4;
    uint32_t *word = address_space_map(cs->as,
                                       page + AVIC_IRR + vector / 32 * 0x10,
                                       &len, true, MEMTXATTRS_UNSPECIFIED);
    uint32_t bit = cpu_to_le32(1u << (vector % 32));

    if (!word) {
        return;
    }
    if (len == 4) {
        if (set) {
            qatomic_or(word, bit);
        } else {
            qatomic_and(word, ~bit);
        }
    }
    address_space_unmap(cs->as, word, len, true, len);
}

/* Has the vCPU look for interrupts its backing page can deliver. */
void svm_avic_request(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);

    cpu_set_interrupt(cs, CPU_INTERRUPT_VIRQ);
    qatomic_set(&cs->neg.icount_decr.u16.high, -1);
}

/*
 * Whether the backing page's IRR holds an interrupt above PPR, which AVIC
 * delivers to the guest as interrupt masking allows (15.29.8.3).
 */
bool svm_avic_has_interrupt(CPUX86State *env)
{
    int vector = avic_highest(env, AVIC_IRR);

    return vector >= 0 && (vector & 0xf0) > (avic_update_ppr(env) & 0xf0);
}

/* The interrupt AVIC delivers next, moved from IRR to ISR; -1 for none. */
int svm_avic_take_interrupt(CPUX86State *env)
{
    int vector = avic_highest(env, AVIC_IRR);
    unsigned int isr;

    if (vector < 0 || (vector & 0xf0) <= (avic_update_ppr(env) & 0xf0)) {
        return -1;
    }
    avic_irr_update(env_cpu(env), env->svm_avic_backing, vector, false);
    isr = AVIC_ISR + vector / 32 * 0x10;
    avic_set(env, isr, avic_get(env, isr) | 1u << (vector % 32));
    avic_update_ppr(env);
    return vector;
}

/*
 * A new TPR, which a write of TPR or of CR8 gave: V_TPR takes its task
 * priority, and PPR follows (15.29.3.1).
 */
void svm_avic_set_tpr(CPUX86State *env, uint32_t tpr)
{
    avic_set(env, AVIC_TPR, tpr);
    env->int_ctl = (env->int_ctl & ~V_TPR_MASK) | ((tpr >> 4) & V_TPR_MASK);
    avic_update_ppr(env);
    svm_avic_request(env);
}

/*
 * A doorbell to the processor with APIC ID APIC_ID, which has a vCPU it
 * runs with AVIC look at its backing page (15.29.8.2).
 */
void svm_avic_doorbell(CPUX86State *env, uint32_t apic_id)
{
    CPUState *target = cpu_by_arch_id(apic_id);

    if (!target) {
        return;
    }
    if (target == env_cpu(env)) {
        if (env->svm_avic) {
            svm_avic_request(env);
        }
    } else if (bql_locked()) {
        cpu_interrupt(target, CPU_INTERRUPT_VIRQ);
    } else {
        bql_lock();
        cpu_interrupt(target, CPU_INTERRUPT_VIRQ);
        bql_unlock();
    }
}

/*
 * An AVIC #VMEXIT, which a trap takes after the instruction, a fault before
 * it, from the state at RETADDR.
 */
static G_NORETURN void avic_exit(CPUX86State *env, uint64_t exit_code,
                                 uint64_t info1, uint64_t info2, bool trap,
                                 uintptr_t retaddr)
{
    CPUState *cs = env_cpu(env);

    x86_stq_phys(cs, env->vm_vmcb + offsetof(struct vmcb, control.exit_info_2),
                 info2);
    if (trap) {
        cpu_restore_state(cs, retaddr);
        x86_pmu_restored_retired(env);
        env->eip = svm_next_rip(env);
        retaddr = 0;
    }
    cpu_vmexit(env, exit_code, info1, retaddr);
}

static G_NORETURN void avic_incomplete_ipi(CPUX86State *env, uint64_t icr,
                                           uint32_t cause, uint32_t index,
                                           uintptr_t retaddr)
{
    avic_exit(env, SVM_EXIT_AVIC_INCOMPLETE_IPI, icr,
              (uint64_t)cause << 32 | index, true, retaddr);
}

static uint64_t avic_physical_entry(CPUX86State *env, uint32_t index)
{
    return x86_ldq_phys(env_cpu(env), env->svm_avic_physical + index * 8);
}

/*
 * The vCPUs of an IPI: the physical APIC ID table entries of its
 * destination, of the logical ones the logical APIC ID table names in
 * xAVIC mode, and of IDs that x2APIC logical destinations give in x2AVIC
 * mode, (cluster << 4) | bit (15.29.5.3).
 */
typedef struct AVICTargets {
    int count;
    uint32_t index[512];
    uint64_t entry[512];
} AVICTargets;

static void avic_add_target(CPUX86State *env, AVICTargets *t, uint64_t icr,
                            uint32_t id, uint32_t index, uintptr_t retaddr)
{
    uint64_t entry;

    if (id > env->svm_avic_max_index) {
        avic_incomplete_ipi(env, icr, AVIC_IPI_BAD_TARGET, index, retaddr);
    }
    entry = avic_physical_entry(env, id);
    if (!(entry & AVIC_PHYS_VALID)) {
        avic_incomplete_ipi(env, icr, AVIC_IPI_BAD_TARGET, index, retaddr);
    }
    t->index[t->count] = id;
    t->entry[t->count++] = entry;
}

static void avic_add_logical(CPUX86State *env, AVICTargets *t, uint64_t icr,
                             uint32_t index, uintptr_t retaddr)
{
    uint32_t entry = x86_ldl_phys(env_cpu(env),
                                  env->svm_avic_logical + index * 4);

    if (!(entry & AVIC_LOGICAL_VALID)) {
        avic_incomplete_ipi(env, icr, AVIC_IPI_BAD_TARGET, index, retaddr);
    }
    avic_add_target(env, t, icr, entry & 0xff, index, retaddr);
}

/*
 * AVIC's IPI for a guest write of ICRL: fixed, edge-triggered interrupts,
 * each target getting the IRR bit and, where its entry says it is running,
 * a doorbell; other targets end in AVIC_INCOMPLETE_IPI, as do other
 * interrupts and targets the tables do not give, before any delivery
 * (15.29.6.1 and 15.29.9.1).
 */
static void avic_ipi(CPUX86State *env, uint32_t icrl, uint32_t dest,
                     uint64_t icr, uintptr_t retaddr)
{
    CPUState *cs = env_cpu(env);
    int vector = icrl & 0xff;
    unsigned int shorthand = (icrl >> 18) & 3;
    bool logical = icrl & (1 << 11);
    uint32_t broadcast_dest = env->svm_x2avic ? 0xffffffff : 0xff;
    /* On the stack: an AVIC_INCOMPLETE_IPI does not return. */
    AVICTargets targets, *t = &targets;
    int not_running = -1;

    t->count = 0;

    if (((icrl >> 8) & 7) || (icrl & (1 << 15))) {
        avic_incomplete_ipi(env, icr, AVIC_IPI_BAD_TYPE, 0, retaddr);
    }
    if (vector < 16) {
        avic_incomplete_ipi(env, icr, AVIC_IPI_BAD_VECTOR, 0, retaddr);
    }
    if (shorthand == 1) {
        avic_irr_update(cs, env->svm_avic_backing, vector, true);
        svm_avic_request(env);
        return;
    }
    if (shorthand || dest == broadcast_dest) {
        for (uint32_t id = 0; id <= env->svm_avic_max_index; id++) {
            uint64_t entry = avic_physical_entry(env, id);

            if (!(entry & AVIC_PHYS_VALID) ||
                (shorthand == 3 &&
                 (entry & AVIC_PHYS_BACKING) == env->svm_avic_backing)) {
                continue;
            }
            t->index[t->count] = id;
            t->entry[t->count++] = entry;
        }
    } else if (!logical) {
        avic_add_target(env, t, icr, dest, dest, retaddr);
    } else if (env->svm_x2avic) {
        for (int bit = 0; bit < 16; bit++) {
            if (dest & (1 << bit)) {
                uint32_t id = (dest >> 16) << 4 | bit;

                avic_add_target(env, t, icr, id, id, retaddr);
            }
        }
    } else if ((avic_get(env, AVIC_DFR) >> 28) == 0xf) {
        for (int bit = 0; bit < 8; bit++) {
            if (dest & (1 << bit)) {
                avic_add_logical(env, t, icr, bit, retaddr);
            }
        }
    } else {
        for (int bit = 0; bit < 4; bit++) {
            if (dest & (1 << bit)) {
                avic_add_logical(env, t, icr, (dest >> 4) * 4 + bit,
                                 retaddr);
            }
        }
    }

    for (int i = 0; i < t->count; i++) {
        avic_irr_update(cs, t->entry[i] & AVIC_PHYS_BACKING, vector, true);
        if (t->entry[i] & AVIC_PHYS_RUNNING) {
            svm_avic_doorbell(env, t->entry[i] & AVIC_PHYS_HOST_ID);
        } else if (not_running < 0) {
            not_running = t->index[i];
        }
    }
    if (not_running >= 0) {
        avic_incomplete_ipi(env, icr, AVIC_IPI_NOT_RUNNING, not_running,
                            retaddr);
    }
}

/*
 * A write of EOI: AVIC retires the highest vector in service but where it
 * is level-triggered, which exits for the hypervisor (15.29.3.1).
 */
static void avic_eoi(CPUX86State *env, uintptr_t retaddr)
{
    int vector = avic_highest(env, AVIC_ISR);
    unsigned int isr;

    if (vector < 0) {
        return;
    }
    if (avic_vector_set(env, AVIC_TMR, vector)) {
        avic_exit(env, SVM_EXIT_AVIC_NOACCEL, AVIC_EOI | 1ULL << 32, vector,
                  true, retaddr);
    }
    isr = AVIC_ISR + vector / 32 * 0x10;
    avic_set(env, isr, avic_get(env, isr) & ~(1u << (vector % 32)));
    avic_update_ppr(env);
    svm_avic_request(env);
}

/*
 * x2AVIC: guest RDMSRs and WRMSRs of 800h-8FFh, which the MSR permission map
 * passed, get the x2APIC's own checks first, as #GP (24593 rev. 3.45, 16.11
 * and Table 16-6), then the register filter, at the xAPIC offset of the MSR
 * (15.29.10). ICR is ICRL and ICRH together, and SELF_IPI sends as ICR does.
 */
static bool x2avic_register(uint32_t msr)
{
    switch (msr) {
    case 0x802 ... 0x803:
    case 0x808 ... 0x80b:
    case 0x80d:
    case 0x80f ... 0x828:
    case 0x830:
    case 0x832 ... 0x839:
    case 0x83e ... 0x842:
    case 0x848 ... 0x857:
        return true;
    default:
        return false;
    }
}

static bool x2avic_read_only(uint32_t msr)
{
    switch (msr) {
    case 0x802 ... 0x803:
    case 0x809 ... 0x80a:
    case 0x80d:
    case 0x810 ... 0x827:
    case 0x839:
    case 0x840:
        return true;
    default:
        return false;
    }
}

/* ICR's must-be-zero bits in x2APIC mode (16.13, Figure 16-34). */
#define X2AVIC_ICR_MBZ  (MAKE_64BIT_MASK(20, 12) | MAKE_64BIT_MASK(16, 2) | \
                         MAKE_64BIT_MASK(12, 2))

static void avic_written(CPUX86State *env, AVICAction action,
                         unsigned int reg, uintptr_t retaddr);

bool svm_x2avic_rdmsr(CPUX86State *env, uint32_t msr, uint64_t *val,
                      uintptr_t retaddr)
{
    unsigned int reg = (msr & 0xff) << 4;

    if (!x2avic_register(msr) || msr == 0x80b || msr == 0x83f) {
        return false;
    }
    if (avic_action(reg, false) == AVIC_FAULT) {
        avic_exit(env, SVM_EXIT_AVIC_NOACCEL, reg, 0, false, retaddr);
    }
    *val = avic_get(env, reg);
    if (msr == 0x830) {
        *val |= (uint64_t)avic_get(env, AVIC_ICRH) << 32;
    }
    return true;
}

bool svm_x2avic_wrmsr(CPUX86State *env, uint32_t msr, uint64_t val,
                      uintptr_t retaddr)
{
    unsigned int reg = (msr & 0xff) << 4;
    AVICAction action = avic_action(reg, true);

    if (!x2avic_register(msr) || x2avic_read_only(msr)) {
        return false;
    }
    if (msr == 0x830 ? (val & X2AVIC_ICR_MBZ) :
        (val >> 32) || ((msr == 0x80b || msr == 0x828) && val) ||
        (msr == 0x83f && val > 0xff)) {
        return false;
    }
    if (msr == 0x83f) {
        uint32_t icrl = 1 << 18 | (uint32_t)val;

        avic_set(env, reg, val);
        avic_ipi(env, icrl, 0, icrl, retaddr);
        return true;
    }
    if (action == AVIC_FAULT) {
        avic_exit(env, SVM_EXIT_AVIC_NOACCEL, reg | 1ULL << 32, 0, false,
                  retaddr);
    }
    avic_set(env, reg, val);
    if (msr == 0x830) {
        avic_set(env, AVIC_ICRH, val >> 32);
    }
    avic_written(env, action, reg, retaddr);
    return true;
}

/* What follows a guest write of a vAPIC register, now in the backing page. */
static void avic_written(CPUX86State *env, AVICAction action,
                         unsigned int reg, uintptr_t retaddr)
{
    switch (action) {
    case AVIC_TRAP:
        avic_exit(env, SVM_EXIT_AVIC_NOACCEL, reg | 1ULL << 32, 0, true,
                  retaddr);
    case AVIC_ACCEL_TPR:
        svm_avic_set_tpr(env, avic_get(env, AVIC_TPR));
        break;
    case AVIC_ACCEL_EOI:
        avic_eoi(env, retaddr);
        break;
    case AVIC_ACCEL_ICR: {
        uint32_t icrl = avic_get(env, AVIC_ICRL);
        uint32_t icrh = avic_get(env, AVIC_ICRH);

        avic_ipi(env, icrl, env->svm_x2avic ? icrh : icrh >> 24,
                 (uint64_t)icrh << 32 | icrl, retaddr);
        break;
    }
    default:
        break;
    }
}

/*
 * xAVIC: guest accesses to its vAPIC page, which TLB entries the nested
 * translation of the page made send here, go to the backing page through
 * the register filter (15.29.3). In VMX non-root operation, those of the
 * APIC-access page come here instead.
 */
static uint64_t avic_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    X86CPU *cpu = opaque;
    CPUX86State *env = &cpu->env;
    unsigned int reg = addr & 0xff0;
    uint8_t buf[8];

    if (env->vmx.nonroot) {
        return x86_vmx_apic_read(env, addr, size, CPU(cpu)->mem_io_pc);
    }
    if (avic_action(reg, false) == AVIC_FAULT) {
        avic_exit(env, SVM_EXIT_AVIC_NOACCEL, reg, 0, false,
                  CPU(cpu)->mem_io_pc);
    }
    address_space_read(CPU(cpu)->as, env->svm_avic_backing + addr,
                       MEMTXATTRS_UNSPECIFIED, buf, size);
    return ldn_le_p(buf, size);
}

static void avic_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                            unsigned size)
{
    X86CPU *cpu = opaque;
    CPUX86State *env = &cpu->env;
    unsigned int reg = addr & 0xff0;
    AVICAction action = avic_action(reg, true);
    uint8_t buf[8];

    if (env->vmx.nonroot) {
        x86_vmx_apic_write(env, addr, val, size, CPU(cpu)->mem_io_pc);
        return;
    }
    if (action == AVIC_FAULT) {
        avic_exit(env, SVM_EXIT_AVIC_NOACCEL, reg | 1ULL << 32, 0, false,
                  CPU(cpu)->mem_io_pc);
    }
    stn_le_p(buf, size, val);
    address_space_write(CPU(cpu)->as, env->svm_avic_backing + addr,
                        MEMTXATTRS_UNSPECIFIED, buf, size);
    avic_written(env, action, reg, CPU(cpu)->mem_io_pc);
}

static const MemoryRegionOps avic_mmio_ops = {
    .read = avic_mmio_read,
    .write = avic_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
};

/* The address space of the guest vAPIC page, whose accesses AVIC filters. */
void svm_avic_init(X86CPU *cpu)
{
    cpu->avic_page = g_new(MemoryRegion, 1);
    memory_region_init_io(cpu->avic_page, OBJECT(cpu), &avic_mmio_ops, cpu,
                          "avic-vapic", TARGET_PAGE_SIZE);
    /*
     * The accesses that end in an AVIC #VMEXIT leave the callbacks by
     * longjmp, which would leave the guard engaged.
     */
    cpu->avic_page->disable_reentrancy_guard = true;
    cpu_address_space_init(CPU(cpu), X86ASIdx_AVIC, "cpu-avic",
                           cpu->avic_page);
}
