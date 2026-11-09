/*
 *  i386 CPU dump to FILE
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
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
#include "qemu/qemu-print.h"
#ifndef CONFIG_USER_ONLY
#include "hw/i386/apic_internal.h"
#include "system/tcg.h"
#endif

/***********************************************************/
/* x86 debug */

static const char * const cc_op_str[] = {
    [CC_OP_DYNAMIC] = "DYNAMIC",

    [CC_OP_EFLAGS] = "EFLAGS",
    [CC_OP_ADCX] = "ADCX",
    [CC_OP_ADOX] = "ADOX",
    [CC_OP_ADCOX] = "ADCOX",

    [CC_OP_MULB] = "MULB",
    [CC_OP_MULW] = "MULW",
    [CC_OP_MULL] = "MULL",
    [CC_OP_MULQ] = "MULQ",

    [CC_OP_ADDB] = "ADDB",
    [CC_OP_ADDW] = "ADDW",
    [CC_OP_ADDL] = "ADDL",
    [CC_OP_ADDQ] = "ADDQ",

    [CC_OP_ADCB] = "ADCB",
    [CC_OP_ADCW] = "ADCW",
    [CC_OP_ADCL] = "ADCL",
    [CC_OP_ADCQ] = "ADCQ",

    [CC_OP_SUBB] = "SUBB",
    [CC_OP_SUBW] = "SUBW",
    [CC_OP_SUBL] = "SUBL",
    [CC_OP_SUBQ] = "SUBQ",

    [CC_OP_SBBB] = "SBBB",
    [CC_OP_SBBW] = "SBBW",
    [CC_OP_SBBL] = "SBBL",
    [CC_OP_SBBQ] = "SBBQ",

    [CC_OP_LOGICB] = "LOGICB",
    [CC_OP_LOGICW] = "LOGICW",
    [CC_OP_LOGICL] = "LOGICL",
    [CC_OP_LOGICQ] = "LOGICQ",

    [CC_OP_INCB] = "INCB",
    [CC_OP_INCW] = "INCW",
    [CC_OP_INCL] = "INCL",
    [CC_OP_INCQ] = "INCQ",

    [CC_OP_DECB] = "DECB",
    [CC_OP_DECW] = "DECW",
    [CC_OP_DECL] = "DECL",
    [CC_OP_DECQ] = "DECQ",

    [CC_OP_SHLB] = "SHLB",
    [CC_OP_SHLW] = "SHLW",
    [CC_OP_SHLL] = "SHLL",
    [CC_OP_SHLQ] = "SHLQ",

    [CC_OP_SARB] = "SARB",
    [CC_OP_SARW] = "SARW",
    [CC_OP_SARL] = "SARL",
    [CC_OP_SARQ] = "SARQ",

    [CC_OP_BMILGB] = "BMILGB",
    [CC_OP_BMILGW] = "BMILGW",
    [CC_OP_BMILGL] = "BMILGL",
    [CC_OP_BMILGQ] = "BMILGQ",

    [CC_OP_POPCNT] = "POPCNT",

    [CC_OP_SBB_SELF] = "SBBx,x",
};

/*
 * A register for dump_table(): its name, or NULL for a cell left blank so
 * that the cells after it keep their columns, its value, and how many
 * hexadecimal digits that takes, if not the table's.
 */
typedef struct DumpCell {
    const char *name;
    uint64_t value;
    int digits;
} DumpCell;

/*
 * A group of registers as rows of NAME=VALUE cells in columns two spaces
 * apart, each column aligned on its equals signs, so that its names end and
 * its values start in line. A row ends at its last named cell. With labels,
 * each row starts with its own, or with blanks as wide as the longest.
 */
static void dump_table(FILE *f, const char *const *labels,
                       const DumpCell *cells, int rows, int cols, int digits)
{
    int names[8] = { 0 }, values[8] = { 0 };
    int indent = 0;
    int row, col, last;

    assert(cols <= ARRAY_SIZE(names));
    for (row = 0; row < rows; row++) {
        if (labels && labels[row]) {
            indent = MAX(indent, (int)strlen(labels[row]) + 2);
        }
        for (col = 0; col < cols; col++) {
            const DumpCell *cell = &cells[row * cols + col];

            if (cell->name) {
                names[col] = MAX(names[col], (int)strlen(cell->name));
                values[col] = MAX(values[col],
                                  cell->digits ? cell->digits : digits);
            }
        }
    }
    for (row = 0; row < rows; row++) {
        const DumpCell *line = &cells[row * cols];

        for (last = cols - 1; last >= 0 && !line[last].name; last--) {
            continue;
        }
        qemu_fprintf(f, "%-*s", indent,
                     labels && labels[row] ? labels[row] : "");
        for (col = 0; col <= last; col++) {
            const DumpCell *cell = &line[col];
            int width = cell->digits ? cell->digits : digits;

            qemu_fprintf(f, "%s", col ? "  " : "");
            if (!cell->name) {
                qemu_fprintf(f, "%*s", names[col] + 1 + values[col], "");
                continue;
            }
            qemu_fprintf(f, "%*s=%0*" PRIx64 "%*s", names[col], cell->name,
                         width, cell->value,
                         col < last ? values[col] - width : 0, "");
        }
        qemu_fprintf(f, "\n");
    }
}

/* The status and control flags, from the highest bit down. */
static void dump_eflags_str(char *buf, int eflags)
{
    static const struct {
        int mask;
        char name;
    } flags[] = {
        { CC_O, 'O' }, { DF_MASK, 'D' }, { IF_MASK, 'I' }, { TF_MASK, 'T' },
        { CC_S, 'S' }, { CC_Z, 'Z' }, { CC_A, 'A' }, { CC_P, 'P' },
        { CC_C, 'C' },
    };
    int i;

    for (i = 0; i < ARRAY_SIZE(flags); i++) {
        buf[i] = (eflags & flags[i].mask) ? flags[i].name : '-';
    }
    buf[i] = '\0';
}

/*
 * The segment registers as a table under a heading: selector, base, limit,
 * and attributes, then, for a descriptor present in protected mode, its DPL
 * and its type.
 */
static void cpu_x86_dump_seg_header(FILE *f, int base_width)
{
    qemu_fprintf(f, "%-3s  %-4s  %-*s  %-8s  %s\n", "", "SEL", base_width,
                 "BASE", "LIMIT", "FLAGS");
}

static void
cpu_x86_dump_seg_cache(CPUX86State *env, FILE *f, int base_width,
                       const char *name, struct SegmentCache *sc)
{
    uint64_t base = base_width == 16 ? sc->base : (uint32_t)sc->base;

    qemu_fprintf(f, "%-3s  %04x  %0*" PRIx64 "  %08x  %08x", name,
                 sc->selector, base_width, base, sc->limit,
                 sc->flags & 0x00ffff00);

    if (!(env->hflags & HF_PE_MASK) || !(sc->flags & DESC_P_MASK)) {
        qemu_fprintf(f, "\n");
        return;
    }

    qemu_fprintf(f, "  DPL=%d  ",
                 (sc->flags & DESC_DPL_MASK) >> DESC_DPL_SHIFT);
    if (sc->flags & DESC_S_MASK) {
        if (sc->flags & DESC_CS_MASK) {
            qemu_fprintf(f, "%s [%c%c", (sc->flags & DESC_L_MASK) ? "CS64" :
                         ((sc->flags & DESC_B_MASK) ? "CS32" : "CS16"),
                         (sc->flags & DESC_C_MASK) ? 'C' : '-',
                         (sc->flags & DESC_R_MASK) ? 'R' : '-');
        } else {
            qemu_fprintf(f, "%s [%c%c", (sc->flags & DESC_B_MASK
                                         || env->hflags & HF_LMA_MASK)
                         ? "DS  " : "DS16",
                         (sc->flags & DESC_E_MASK) ? 'E' : '-',
                         (sc->flags & DESC_W_MASK) ? 'W' : '-');
        }
        qemu_fprintf(f, "%c]\n", (sc->flags & DESC_A_MASK) ? 'A' : '-');
    } else {
        static const char *sys_type_name[2][16] = {
            { /* 32 bit mode */
                "Reserved", "TSS16-avl", "LDT", "TSS16-busy",
                "CallGate16", "TaskGate", "IntGate16", "TrapGate16",
                "Reserved", "TSS32-avl", "Reserved", "TSS32-busy",
                "CallGate32", "Reserved", "IntGate32", "TrapGate32"
            },
            { /* 64 bit mode */
                "<hiword>", "Reserved", "LDT", "Reserved", "Reserved",
                "Reserved", "Reserved", "Reserved", "Reserved",
                "TSS64-avl", "Reserved", "TSS64-busy", "CallGate64",
                "Reserved", "IntGate64", "TrapGate64"
            }
        };
        qemu_fprintf(f, "%s\n",
                     sys_type_name[(env->hflags & HF_LMA_MASK) ? 1 : 0]
                     [(sc->flags & DESC_TYPE_MASK) >> DESC_TYPE_SHIFT]);
    }
}

#ifndef CONFIG_USER_ONLY

/* ARRAY_SIZE check is not required because
 * DeliveryMode(dm) has a size of 3 bit.
 */
static inline const char *dm2str(uint32_t dm)
{
    static const char *str[] = {
        "Fixed",
        "...",
        "SMI",
        "...",
        "NMI",
        "INIT",
        "...",
        "ExtINT"
    };
    return str[dm];
}

static void dump_apic_lvt(const char *name, uint32_t lvt, bool is_timer)
{
    uint32_t dm = (lvt & APIC_LVT_DELIV_MOD) >> APIC_LVT_DELIV_MOD_SHIFT;
    qemu_printf("%s\t 0x%08x %s %-5s %-6s %-7s %-12s %-6s",
                name, lvt,
                lvt & APIC_LVT_INT_POLARITY ? "active-lo" : "active-hi",
                lvt & APIC_LVT_LEVEL_TRIGGER ? "level" : "edge",
                lvt & APIC_LVT_MASKED ? "masked" : "",
                lvt & APIC_LVT_DELIV_STS ? "pending" : "",
                !is_timer ?
                    "" : lvt & APIC_LVT_TIMER_PERIODIC ?
                            "periodic" : lvt & APIC_LVT_TIMER_TSCDEADLINE ?
                                            "tsc-deadline" : "one-shot",
                dm2str(dm));
    if (dm != APIC_DM_NMI) {
        qemu_printf(" (vec %u)\n", lvt & APIC_VECTOR_MASK);
    } else {
        qemu_printf("\n");
    }
}

/* ARRAY_SIZE check is not required because
 * destination shorthand has a size of 2 bit.
 */
static inline const char *shorthand2str(uint32_t shorthand)
{
    const char *str[] = {
        "no-shorthand", "self", "all-self", "all"
    };
    return str[shorthand];
}

static inline uint8_t divider_conf(uint32_t divide_conf)
{
    uint8_t divide_val = ((divide_conf & 0x8) >> 1) | (divide_conf & 0x3);

    return divide_val == 7 ? 1 : 2 << divide_val;
}

static inline void mask2str(char *str, uint32_t val, uint8_t size)
{
    while (size--) {
        *str++ = (val >> size) & 1 ? '1' : '0';
    }
    *str = 0;
}

#define MAX_LOGICAL_APIC_ID_MASK_SIZE 16

static void dump_apic_icr(APICCommonState *s, CPUX86State *env)
{
    uint32_t icr = s->icr[0], icr2 = s->icr[1];
    uint8_t dest_shorthand = \
        (icr & APIC_ICR_DEST_SHORT) >> APIC_ICR_DEST_SHORT_SHIFT;
    bool logical_mod = icr & APIC_ICR_DEST_MOD;
    char apic_id_str[MAX_LOGICAL_APIC_ID_MASK_SIZE + 1];
    uint32_t dest_field;
    bool x2apic;

    qemu_printf("ICR\t 0x%08x %s %s %s %s\n",
                icr,
                logical_mod ? "logical" : "physical",
                icr & APIC_ICR_TRIGGER_MOD ? "level" : "edge",
                icr & APIC_ICR_LEVEL ? "assert" : "de-assert",
                shorthand2str(dest_shorthand));

    qemu_printf("ICR2\t 0x%08x", icr2);
    if (dest_shorthand != 0) {
        qemu_printf("\n");
        return;
    }
    x2apic = env->features[FEAT_1_ECX] & CPUID_EXT_X2APIC;
    dest_field = x2apic ? icr2 : icr2 >> APIC_ICR_DEST_SHIFT;

    if (!logical_mod) {
        if (x2apic) {
            qemu_printf(" cpu %u (X2APIC ID)\n", dest_field);
        } else {
            qemu_printf(" cpu %u (APIC ID)\n",
                        dest_field & APIC_LOGDEST_XAPIC_ID);
        }
        return;
    }

    if (s->dest_mode == 0xf) { /* flat mode */
        mask2str(apic_id_str, icr2 >> APIC_ICR_DEST_SHIFT, 8);
        qemu_printf(" mask %s (APIC ID)\n", apic_id_str);
    } else if (s->dest_mode == 0) { /* cluster mode */
        if (x2apic) {
            mask2str(apic_id_str, dest_field & APIC_LOGDEST_X2APIC_ID, 16);
            qemu_printf(" cluster %u mask %s (X2APIC ID)\n",
                        dest_field >> APIC_LOGDEST_X2APIC_SHIFT, apic_id_str);
        } else {
            mask2str(apic_id_str, dest_field & APIC_LOGDEST_XAPIC_ID, 4);
            qemu_printf(" cluster %u mask %s (APIC ID)\n",
                        dest_field >> APIC_LOGDEST_XAPIC_SHIFT, apic_id_str);
        }
    }
}

static void dump_apic_interrupt(const char *name, uint32_t *ireg_tab,
                                uint32_t *tmr_tab)
{
    int i, empty = true;

    qemu_printf("%s\t ", name);
    for (i = 0; i < 256; i++) {
        if (apic_get_bit(ireg_tab, i)) {
            qemu_printf("%u%s ", i,
                        apic_get_bit(tmr_tab, i) ? "(level)" : "");
            empty = false;
        }
    }
    qemu_printf("%s\n", empty ? "(none)" : "");
}

/* The APIC base and the mode it sets, which firmware may have locked. */
static void dump_apic_base(APICCommonState *s)
{
    qemu_printf("BASE\t 0x%08x %s%s\n", s->apicbase,
                !(s->apicbase & MSR_IA32_APICBASE_ENABLE) ? "disabled" :
                s->apicbase & MSR_IA32_APICBASE_EXTD ? "x2APIC" : "xAPIC",
                s->cpu->x2apic_locked ? ", locked" : "");
}

/*
 * AMD's extended APIC space: its feature and control registers, the vectors
 * that the interrupt enable registers disable, when they are on, and the
 * extended LVT entries.
 */
static void dump_apic_ext(APICCommonState *s)
{
    bool disabled = false;
    int i;

    if (!(s->cpu->env.features[FEAT_8000_0001_ECX] & CPUID_EXT3_EXTAPIC)) {
        return;
    }
    qemu_printf("EFR\t 0x%08x ECTRL 0x%08x\n", apic_get_ext_feature(s),
                s->ext_ctrl);
    if (s->ext_ctrl & APIC_EXT_CTRL_IER) {
        qemu_printf("IER\t ");
        for (i = 0; i < 256; i++) {
            if (!apic_get_bit(s->ier, i)) {
                qemu_printf("%u ", i);
                disabled = true;
            }
        }
        qemu_printf("%s\n", disabled ? "disabled" : "(none disabled)");
    }
    for (i = 0; i < s->cpu->extapic_lvts; i++) {
        uint32_t lvt = s->eilvt[i];

        qemu_printf("EILVT%d\t 0x%08x %-6s %-7s %-6s (vec %u)\n", i, lvt,
                    lvt & APIC_LVT_MASKED ? "masked" : "",
                    lvt & APIC_LVT_DELIV_STS ? "pending" : "",
                    dm2str((lvt & APIC_LVT_DELIV_MOD) >>
                           APIC_LVT_DELIV_MOD_SHIFT),
                    lvt & APIC_VECTOR_MASK);
    }
}

void x86_cpu_dump_local_apic_state(CPUState *cs, int flags)
{
    X86CPU *cpu = X86_CPU(cs);
    APICCommonState *s = cpu->apic_state;
    if (!s) {
        qemu_printf("local apic state not available\n");
        return;
    }
    uint32_t *lvt = s->lvt;

    qemu_printf("dumping local APIC state for CPU %-2u\n\n",
                CPU(cpu)->cpu_index);
    dump_apic_base(s);
    dump_apic_lvt("LVT0", lvt[APIC_LVT_LINT0], false);
    dump_apic_lvt("LVT1", lvt[APIC_LVT_LINT1], false);
    dump_apic_lvt("LVTPC", lvt[APIC_LVT_PERFORM], false);
    dump_apic_lvt("LVTERR", lvt[APIC_LVT_ERROR], false);
    dump_apic_lvt("LVTTHMR", lvt[APIC_LVT_THERMAL], false);
    dump_apic_lvt("LVTT", lvt[APIC_LVT_TIMER], true);

    qemu_printf("Timer\t DCR=0x%x (divide by %u) initial_count = %u"
                " current_count = %u",
                s->divide_conf & APIC_DCR_MASK,
                divider_conf(s->divide_conf),
                s->initial_count, apic_get_current_count(s));
    if (lvt[APIC_LVT_TIMER] & APIC_LVT_TIMER_TSCDEADLINE) {
        qemu_printf(" tsc_deadline = 0x%" PRIx64, cpu->env.tsc_deadline);
    }
    qemu_printf("\n");

    qemu_printf("SPIV\t 0x%08x APIC %s, focus=%s, spurious vec %u\n",
                s->spurious_vec,
                s->spurious_vec & APIC_SPURIO_ENABLED ? "enabled" : "disabled",
                s->spurious_vec & APIC_SPURIO_FOCUS ? "on" : "off",
                s->spurious_vec & APIC_VECTOR_MASK);

    dump_apic_icr(s, &cpu->env);

    qemu_printf("ESR\t 0x%08x\n", s->esr);
    dump_apic_ext(s);

    dump_apic_interrupt("ISR", s->isr, s->tmr);
    dump_apic_interrupt("IRR", s->irr, s->tmr);

    qemu_printf("\nAPR 0x%02x TPR 0x%02x DFR 0x%02x LDR 0x%02x",
                s->arb_id, s->tpr, s->dest_mode, s->log_dest);
    if (s->dest_mode == 0) {
        qemu_printf("(cluster %u: id %u)",
                    s->log_dest >> APIC_LOGDEST_XAPIC_SHIFT,
                    s->log_dest & APIC_LOGDEST_XAPIC_ID);
    }
    qemu_printf(" PPR 0x%02x\n", apic_get_ppr(s));
}

#endif /* !CONFIG_USER_ONLY */

#define DUMP_CODE_BYTES_TOTAL    50
#define DUMP_CODE_BYTES_BACKWARD 20
/* As many as come before EIP, which then begins the second row. */
#define DUMP_CODE_BYTES_ROW      20

#if !defined(CONFIG_USER_ONLY)
/*
 * Whether a dump shows the state of a feature that the processor HAS: a
 * full one, as "info registers" makes, does, and others while the feature
 * is ENABLED.
 */
static bool dump_feature(int flags, bool has, bool enabled)
{
    return has && ((flags & CPU_DUMP_FPU) || enabled);
}

/*
 * TCG's VMX operation and SVM: root or non-root operation, with the VMXON
 * region, the current VMCS and its launch state, and host or guest mode,
 * with the host save area, the last VMCB, GIF, the nested page tables, the
 * bus lock counter, and VM_CR.
 */
static void dump_virt(CPUX86State *env, FILE *f)
{
    bool svm = env->efer & MSR_EFER_SVME;
    const char *labels[4] = { NULL };
    DumpCell cells[4][3] = { 0 };
    int rows = 0;

    if (!tcg_enabled()) {
        return;
    }
    if (env->vmx.on) {
        labels[rows] = env->vmx.nonroot ? "VMX  non-root" : "VMX  root";
        cells[rows][0] = (DumpCell) { "VMXON", env->vmx.vmxon_ptr };
        cells[rows][1] = (DumpCell) { "VMCS", env->vmx.vmcs_ptr };
        cells[rows][2] = (DumpCell) { "LAUNCHED", env->vmx.vmcs_launched, 1 };
        rows++;
    }
    if (svm) {
        bool guest = env->hflags & HF_GUEST_MASK;
        bool npt = guest && (env->hflags2 & HF2_NPT_MASK);
        bool bus_locks = guest &&
                         (env->intercept_vec5 &
                          (1 << (SVM_EXIT_BUSLOCK - SVM_EXIT_INVLPGB)));

        labels[rows] = guest ? "SVM  guest" : "SVM  host";
        cells[rows][0] = (DumpCell) { "HSAVE", env->vm_hsave };
        cells[rows][1] = (DumpCell) { "VMCB", env->vm_vmcb };
        cells[rows][2] = (DumpCell) { "GIF",
                                      !!(env->hflags2 & HF2_GIF_MASK), 1 };
        rows++;
        if (npt || bus_locks) {
            if (npt) {
                cells[rows][0] = (DumpCell) { "N_CR3", env->nested_cr3 };
                cells[rows][1] = (DumpCell) { "G_PAT", env->svm_gpat };
            }
            if (bus_locks) {
                cells[rows][2] = (DumpCell) { "BUS_LOCKS",
                                              env->svm_bus_lock_counter, 4 };
            }
            rows++;
        }
    }
    /* VM_CR under the SVM state, or on its own while EFER.SVME is clear. */
    if (env->vm_cr) {
        labels[rows] = svm ? NULL : "SVM  off";
        cells[rows][0] = (DumpCell) { "VM_CR", env->vm_cr };
        rows++;
    }
    if (rows) {
        qemu_fprintf(f, "\n");
        dump_table(f, labels, &cells[0][0], rows, 3, 16);
    }
}

/* CET's MSRs and SSP, and the shadow stack pointers of each level. */
static void dump_cet(CPUX86State *env, FILE *f, int flags)
{
    bool has = (env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_CET_SHSTK) ||
               (env->features[FEAT_7_0_EDX] & CPUID_7_0_EDX_CET_IBT);
    DumpCell cells[4][2] = {
        { { "S_CET", env->s_cet }, { "U_CET", env->u_cet } },
        { { "SSP", env->guest_ssp } },
        { { "PL0_SSP", env->pl0_ssp }, { "PL1_SSP", env->pl1_ssp } },
        { { "PL2_SSP", env->pl2_ssp }, { "PL3_SSP", env->pl3_ssp } },
    };

    if (!dump_feature(flags, has, env->cr[4] & CR4_CET_MASK)) {
        return;
    }
#ifdef TARGET_X86_64
    cells[1][1] = (DumpCell) { "ISST", env->int_ssp_table };
#endif
    qemu_fprintf(f, "\n");
    dump_table(f, NULL, &cells[0][0], 4, 2, 16);
}

/* User interrupts' MSRs and UIF (Intel SDM 325462-093 Vol. 3A, 9.3). */
static void dump_uintr(CPUX86State *env, FILE *f, int flags)
{
    const DumpCell cells[4][2] = {
        { { "UINTR_HANDLER", env->uintr_handler },
          { "UINTR_STACKADJUST", env->uintr_stackadjust } },
        { { "UINTR_MISC", env->uintr_misc }, { "UINTR_PD", env->uintr_pd } },
        { { "UINTR_TT", env->uintr_tt }, { "UINTR_RR", env->uintr_rr } },
        { { "UIF", env->uif, 1 } },
    };

    if (!dump_feature(flags,
                      env->features[FEAT_7_0_EDX] & CPUID_7_0_EDX_UINTR,
                      env->cr[4] & CR4_UINTR_MASK)) {
        return;
    }
    qemu_fprintf(f, "\n");
    dump_table(f, NULL, &cells[0][0], 4, 2, 16);
}

/*
 * MSR_MEMORY_CTRL's bus-lock controls, and TCG's DebugCtl and its last
 * branch and last exception records.
 */
static void dump_lbr(CPUX86State *env, FILE *f, int flags)
{
    bool lbr = tcg_enabled() &&
               dump_feature(flags, true,
                            env->debugctl & (DEBUGCTL_LBR | DEBUGCTL_BTF |
                                             DEBUGCTL_BLD));
    DumpCell cells[4][2] = { 0 };
    int rows = 0;

    if (tcg_enabled() && env->memory_ctrl) {
        cells[rows++][0] = (DumpCell) { "MEMORY_CTRL", env->memory_ctrl };
    }
    if (lbr) {
        cells[rows++][0] = (DumpCell) { "DEBUGCTL", env->debugctl };
        cells[rows][0] = (DumpCell) { "LBR_FROM", (uint64_t)env->lbr_from };
        cells[rows++][1] = (DumpCell) { "LBR_TO", (uint64_t)env->lbr_to };
        cells[rows][0] = (DumpCell) { "LER_FROM",
                                      (uint64_t)env->lbr_int_from };
        cells[rows++][1] = (DumpCell) { "LER_TO", (uint64_t)env->lbr_int_to };
    }
    if (rows) {
        qemu_fprintf(f, "\n");
        dump_table(f, NULL, &cells[0][0], rows, 2, 16);
    }
}

/*
 * The FRED MSRs (Intel SDM 325462-093 Vol. 3A, 8.2.3), each level's stack
 * and shadow stack pointers in one column.
 */
static void dump_fred(CPUX86State *env, FILE *f, int flags)
{
#ifdef TARGET_X86_64
    const DumpCell cells[5][2] = {
        { { "FRED_CONFIG", env->fred_config },
          { "FRED_STKLVLS", env->fred_stklvls } },
        { { "FRED_RSP0", env->fred_rsp0 }, { "FRED_RSP1", env->fred_rsp1 } },
        { { "FRED_RSP2", env->fred_rsp2 }, { "FRED_RSP3", env->fred_rsp3 } },
        { { NULL, 0 }, { "FRED_SSP1", env->fred_ssp1 } },
        { { "FRED_SSP2", env->fred_ssp2 }, { "FRED_SSP3", env->fred_ssp3 } },
    };

    if (!dump_feature(flags, env->features[FEAT_7_1_EAX] & CPUID_7_1_EAX_FRED,
                      env->cr[4] & CR4_FRED_MASK)) {
        return;
    }
    qemu_fprintf(f, "\n");
    dump_table(f, NULL, &cells[0][0], 5, 2, 16);
#endif
}
#endif

/*
 * The general-purpose registers, 32 bits wide outside 64-bit code, four to a
 * row, or three when 64 bits wide: the first eight, then R8-R15, then APX's
 * R16-R31 where the processor has them, each group from a row of its own.
 */
static void dump_gprs(CPUX86State *env, FILE *f, bool wide)
{
    static const int order[8] = {
        R_EAX, R_EBX, R_ECX, R_EDX, R_ESI, R_EDI, R_EBP, R_ESP
    };
    static const char * const names[2][8] = {
        { "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP" },
        { "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP" },
    };
    static const int groups[] = { 8, 8, 16 };
    int cols = wide ? 3 : 4;
    /* Twelve rows of three at most: three, three and six. */
    DumpCell cells[12 * 3] = { 0 };
    int count = 8, n = 0, rows = 0;
    int group, i;
#ifdef TARGET_X86_64
    static const char * const numbered[CPU_NB_EREGS64 - 8] = {
        "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
        "R16", "R17", "R18", "R19", "R20", "R21", "R22", "R23",
        "R24", "R25", "R26", "R27", "R28", "R29", "R30", "R31",
    };

    if (wide) {
        count = (env->features[FEAT_7_1_EDX] & CPUID_7_1_EDX_APXF) ? 32 : 16;
    }
#endif
    for (group = 0; n < count; group++) {
        for (i = 0; i < groups[group]; i++, n++) {
            DumpCell *cell = &cells[rows * cols + i];

#ifdef TARGET_X86_64
            if (n >= 8) {
                *cell = (DumpCell) { numbered[n - 8], env->regs[n] };
                continue;
            }
#endif
            *cell = (DumpCell) { names[wide][n],
                                 wide ? (uint64_t)env->regs[order[n]]
                                      : (uint32_t)env->regs[order[n]] };
        }
        rows += DIV_ROUND_UP(groups[group], cols);
    }
    dump_table(f, NULL, cells, rows, cols, wide ? 16 : 8);
}

/*
 * RIP, RFLAGS with its flags decoded, and the processor's modes, and under
 * them, if wanted, TCG's lazily computed flags.
 */
static void dump_state(CPUState *cs, CPUX86State *env, FILE *f, int flags,
                       bool wide)
{
    int digits = wide ? 16 : 8;
    uint64_t mask = wide ? UINT64_MAX : UINT32_MAX;
    int eflags = cpu_compute_eflags(env);
    char eflags_buf[16], rfl[32];

    dump_eflags_str(eflags_buf, eflags);
    snprintf(rfl, sizeof(rfl), "%s=%08x [%s]", wide ? "RFL" : "EFL", eflags,
             eflags_buf);
    qemu_fprintf(f, "%s=%0*" PRIx64 "  %s  CPL=%d II=%d A20=%d SMM=%d HLT=%d\n",
                 wide ? "RIP" : "EIP", digits, (uint64_t)env->eip & mask, rfl,
                 env->hflags & HF_CPL_MASK,
                 (env->hflags >> HF_INHIBIT_IRQ_SHIFT) & 1,
                 (env->a20_mask >> 20) & 1,
                 (env->hflags >> HF_SMM_SHIFT) & 1,
                 cs->halted);
    if (flags & CPU_DUMP_CCOP) {
        const char *cc_op_name = NULL;
        char cc_op_buf[32];

        if ((unsigned)env->cc_op < ARRAY_SIZE(cc_op_str)) {
            cc_op_name = cc_op_str[env->cc_op];
        }
        if (cc_op_name == NULL) {
            snprintf(cc_op_buf, sizeof(cc_op_buf), "[%d]", env->cc_op);
            cc_op_name = cc_op_buf;
        }
        /* CCO under CPL, past RFLAGS's decoded flags. */
        qemu_fprintf(f, "CCS=%0*" PRIx64 "  CCD=%0*" PRIx64 "%*sCCO=%s\n",
                     digits, (uint64_t)env->cc_src & mask,
                     digits, (uint64_t)env->cc_dst & mask,
                     (int)strlen(rfl) - (4 + digits) + 2, "", cc_op_name);
    }
}

/*
 * The control registers and the debug registers, 64 bits wide in long mode,
 * else 32 bits wide, and EFER, a blank line apart.
 */
static void dump_system_regs(CPUX86State *env, FILE *f, bool lma)
{
    if (lma) {
        const DumpCell crs[2][3] = {
            { { "CR0", env->cr[0] }, { "CR2", env->cr[2] },
              { "CR3", env->cr[3] } },
            { { "CR4", env->cr[4] } },
        };
        /* Two to a row, so that DR3 keeps to the other breakpoints. */
        const DumpCell drs[3][2] = {
            { { "DR0", env->dr[0] }, { "DR1", env->dr[1] } },
            { { "DR2", env->dr[2] }, { "DR3", env->dr[3] } },
            { { "DR6", env->dr[6] }, { "DR7", env->dr[7] } },
        };

        dump_table(f, NULL, &crs[0][0], 2, 3, 16);
        qemu_fprintf(f, "\n");
        dump_table(f, NULL, &drs[0][0], 3, 2, 16);
    } else {
        const DumpCell crs[4] = {
            { "CR0", (uint32_t)env->cr[0] }, { "CR2", (uint32_t)env->cr[2] },
            { "CR3", (uint32_t)env->cr[3] }, { "CR4", (uint32_t)env->cr[4] },
        };
        const DumpCell drs[2][4] = {
            { { "DR0", (uint32_t)env->dr[0] }, { "DR1", (uint32_t)env->dr[1] },
              { "DR2", (uint32_t)env->dr[2] },
              { "DR3", (uint32_t)env->dr[3] } },
            { { "DR6", (uint32_t)env->dr[6] },
              { "DR7", (uint32_t)env->dr[7] } },
        };

        dump_table(f, NULL, crs, 1, 4, 8);
        qemu_fprintf(f, "\n");
        dump_table(f, NULL, &drs[0][0], 2, 4, 8);
    }
    qemu_fprintf(f, "\nEFER=%016" PRIx64 "\n", env->efer);
}

/*
 * The x87 registers under their control, status and tag words, which share a
 * row with MXCSR.
 */
static void dump_fpu_regs(CPUX86State *env, FILE *f)
{
    int fptag = 0;
    int i;

    for (i = 0; i < 8; i++) {
        fptag |= ((!env->fptags[i]) << i);
    }
    update_mxcsr_from_sse_status(env);
    qemu_fprintf(f, "FCW=%04x  FSW=%04x [ST=%d]  FTW=%02x  MXCSR=%08x\n\n",
                 env->fpuc,
                 (env->fpus & ~0x3800) | (env->fpstt & 0x7) << 11,
                 env->fpstt,
                 fptag,
                 env->mxcsr);
    for (i = 0; i < 8; i++) {
        CPU_LDoubleU u;
        u.d = env->fpregs[i].d;
        qemu_fprintf(f, "FPR%d=%016" PRIx64 " %04x%s",
                     i, u.l.lower, u.l.upper, (i & 1) ? "\n" : "  ");
    }
}

/*
 * The vector registers, as wide as XCR0 makes them: an XMM register to a row,
 * a YMM register to a row, or a ZMM register over two, its upper half first,
 * with the AVX-512 opmask registers before them.
 */
static void dump_vector_regs(CPUX86State *env, FILE *f)
{
    const uint64_t avx512_mask = XSTATE_OPMASK_MASK | XSTATE_ZMM_Hi256_MASK |
                                 XSTATE_Hi16_ZMM_MASK | XSTATE_YMM_MASK |
                                 XSTATE_SSE_MASK;
    const uint64_t avx_mask = XSTATE_YMM_MASK | XSTATE_SSE_MASK;
    bool wide = env->hflags & HF_CS64_MASK;
    int i;

    if ((env->xcr0 & avx512_mask) == avx512_mask) {
        static const char * const names[NB_OPMASK_REGS] = {
            "K0", "K1", "K2", "K3", "K4", "K5", "K6", "K7",
        };
        DumpCell opmasks[3][3] = { 0 };

        for (i = 0; i < NB_OPMASK_REGS; i++) {
            opmasks[i / 3][i % 3] = (DumpCell) { names[i],
                                                 env->opmask_regs[i] };
        }
        qemu_fprintf(f, "\n");
        dump_table(f, NULL, &opmasks[0][0], 3, 3, 16);
        qemu_fprintf(f, "\n");
        for (i = 0; i < (wide ? 32 : 8); i++) {
            qemu_fprintf(f, "ZMM%02d=%016" PRIx64 " %016" PRIx64 " %016" PRIx64
                         " %016" PRIx64 "\n", i,
                         env->xmm_regs[i].ZMM_Q(7), env->xmm_regs[i].ZMM_Q(6),
                         env->xmm_regs[i].ZMM_Q(5), env->xmm_regs[i].ZMM_Q(4));
            qemu_fprintf(f, "%6s%016" PRIx64 " %016" PRIx64 " %016" PRIx64
                         " %016" PRIx64 "\n", "",
                         env->xmm_regs[i].ZMM_Q(3), env->xmm_regs[i].ZMM_Q(2),
                         env->xmm_regs[i].ZMM_Q(1), env->xmm_regs[i].ZMM_Q(0));
        }
    } else if ((env->xcr0 & avx_mask) == avx_mask) {
        qemu_fprintf(f, "\n");
        for (i = 0; i < (wide ? 16 : 8); i++) {
            qemu_fprintf(f, "YMM%02d=%016" PRIx64 " %016" PRIx64 " %016" PRIx64
                         " %016" PRIx64 "\n", i,
                         env->xmm_regs[i].ZMM_Q(3), env->xmm_regs[i].ZMM_Q(2),
                         env->xmm_regs[i].ZMM_Q(1), env->xmm_regs[i].ZMM_Q(0));
        }
    } else {
        qemu_fprintf(f, "\n");
        for (i = 0; i < (wide ? 16 : 8); i++) {
            qemu_fprintf(f, "XMM%02d=%016" PRIx64 " %016" PRIx64 "\n", i,
                         env->xmm_regs[i].ZMM_Q(1), env->xmm_regs[i].ZMM_Q(0));
        }
    }
}

/*
 * The registers in groups a blank line apart, each aligned within its
 * columns and no line over 79 characters.
 */
void x86_cpu_dump_state(CPUState *cs, FILE *f, int flags)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    static const char *seg_name[6] = { "ES", "CS", "SS", "DS", "FS", "GS" };
    bool wide = false, lma = false;
    int width, i;
    uint64_t mask;

#ifdef TARGET_X86_64
    wide = env->hflags & HF_CS64_MASK;
    lma = env->hflags & HF_LMA_MASK;
#endif
    dump_gprs(env, f, wide);
    qemu_fprintf(f, "\n");
    dump_state(cs, env, f, flags, wide);

    /* In long mode the system registers are 64 bits wide, if not all used. */
    width = lma ? 16 : 8;
    mask = lma ? UINT64_MAX : UINT32_MAX;

    qemu_fprintf(f, "\n");
    cpu_x86_dump_seg_header(f, width);
    for (i = 0; i < 6; i++) {
        cpu_x86_dump_seg_cache(env, f, width, seg_name[i], &env->segs[i]);
    }
    cpu_x86_dump_seg_cache(env, f, width, "LDT", &env->ldt);
    cpu_x86_dump_seg_cache(env, f, width, "TR", &env->tr);
    qemu_fprintf(f, "%-3s  %4s  %0*" PRIx64 "  %08x\n", "GDT", "", width,
                 env->gdt.base & mask, env->gdt.limit);
    qemu_fprintf(f, "%-3s  %4s  %0*" PRIx64 "  %08x\n", "IDT", "", width,
                 env->idt.base & mask, env->idt.limit);

    qemu_fprintf(f, "\n");
    dump_system_regs(env, f, lma);
#if !defined(CONFIG_USER_ONLY)
    dump_virt(env, f);
    dump_cet(env, f, flags);
    dump_uintr(env, f, flags);
    dump_fred(env, f, flags);
    dump_lbr(env, f, flags);
#endif
    if (flags & CPU_DUMP_FPU) {
        qemu_fprintf(f, "\n");
        dump_fpu_regs(env, f);
        dump_vector_regs(env, f);
    }
    if (flags & CPU_DUMP_CODE) {
        target_ulong base = env->segs[R_CS].base + env->eip;
        target_ulong offs = MIN(env->eip, DUMP_CODE_BYTES_BACKWARD);
        uint8_t code;
        char codestr[3];

        qemu_fprintf(f, "\nCode=");
        for (i = 0; i < DUMP_CODE_BYTES_TOTAL; i++) {
            if (cpu_memory_rw_debug(cs, base - offs + i, &code, 1, 0) == 0) {
                snprintf(codestr, sizeof(codestr), "%02x", code);
            } else {
                snprintf(codestr, sizeof(codestr), "??");
            }
            qemu_fprintf(f, "%s%s%s%s",
                         !i ? "" :
                         i % DUMP_CODE_BYTES_ROW ? " " : "\n     ",
                         i == offs ? "<" : "", codestr, i == offs ? ">" : "");
        }
        qemu_fprintf(f, "\n");
    }
}
