#ifndef APIC_H
#define APIC_H

typedef struct APICCommonState APICCommonState;

/* apic.c */
void apic_set_max_apic_id(uint32_t max_apic_id);
int apic_accept_pic_intr(APICCommonState *s);
void apic_deliver_pic_intr(APICCommonState *s, int level);
void apic_deliver_nmi(APICCommonState *s);
void apic_deliver_pmi(APICCommonState *s, bool mask);
int apic_get_interrupt(APICCommonState *s);
int cpu_set_apic_base(APICCommonState *s, uint64_t val);
uint64_t cpu_get_apic_base(APICCommonState *s);
bool cpu_is_apic_enabled(APICCommonState *s);
void cpu_set_apic_tpr(APICCommonState *s, uint8_t val);
uint8_t cpu_get_apic_tpr(APICCommonState *s);
void apic_init_reset(APICCommonState *s);
void apic_sipi(APICCommonState *s);
void apic_poll_irq(APICCommonState *s);
void apic_write_eoi(APICCommonState *s);
int apic_get_sipi_vector(APICCommonState *s);
void apic_send_fixed_ipi(uint32_t dest, uint8_t vector);
void apic_send_user_ipi(APICCommonState *s, uint32_t ndst, uint8_t vector);
void apic_designate_bsp(APICCommonState *s, bool bsp);
int apic_get_highest_priority_irr(APICCommonState *s);
int apic_msr_read(APICCommonState *s, int index, uint64_t *val);
uint64_t apic_get_tsc_deadline(APICCommonState *s);
void apic_set_tsc_deadline(APICCommonState *s, uint64_t deadline);
void apic_tsc_changed(APICCommonState *s);
int apic_msr_write(APICCommonState *s, int index, uint64_t val);
bool is_x2apic_mode(APICCommonState *s);

/* pc.c */
APICCommonState *cpu_get_current_apic(void);

#endif
