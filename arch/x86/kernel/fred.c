/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/ptrace.h>
#include <linux/nospec.h>
#include <linux/percpu.h>

#include <asm/desc.h>
#include <asm/idtentry.h>
#include <asm/syscall.h>
#include <asm/tlbflush.h>	/* For cr4_set_bits() */
#include <asm/traps.h>
#include <asm/fred.h>

static __always_inline DECLARE_FRED_HANDLER(fred_emulate_trap)
{
	struct fred_info * const fi = fred_info(regs);

	fi->type    = EXTYPE_SWFAULT;
	fi->errcode = error_code;
	fi->vector  = vector;

	fred_exception(regs, error_code, vector);
}

static __always_inline DECLARE_FRED_HANDLER(fred_emulate_fault)
{
	regs->ip -= 2;		/* XXX: replace with real instruction len */
	fred_emulate_trap(regs, error_code, vector);
}

/*
 * Emulate SYSENTER if applicable. This is not the preferred system
 * call in 32-bit mode under FRED, rather int $0x80 is preferred and
 * exported in the vdso. SYSCALL proper has a hard-coded early out in
 * fred_entry_from_user().
 */
DEFINE_FRED_HANDLER(fred_syscall_slow)
{
	if (IS_ENABLED(CONFIG_IA32_EMULATION) &&
	    likely(vector == FRED_SYSENTER))
		do_fast_syscall_32(regs);
	else
		fred_emulate_fault(regs, 0, X86_TRAP_UD);
}

/*
 * Some software exceptions can also be triggered as int instructions,
 * for historical reasons. Implement those here. The performance-critical
 * int $0x80 (32-bit system call) has a hard-coded early out in
 * fred_entry_from_user().
 */
DEFINE_FRED_HANDLER(fred_sw_interrupt_user)
{
	switch (vector) {
	case X86_TRAP_BP:
	case X86_TRAP_OF:
		fred_emulate_trap(regs, 0, vector);
		break;
	default:
		fred_emulate_fault(regs, 0, X86_TRAP_GP);
		break;
	}
}

/*
 * Exception entry
 */
#define X86_MAX_TRAP 31

DEFINE_FRED_HANDLER(fred_exception)
{
	/*
	 * This intentially omits exceptions that cannot happen on FRED h/w:
	 * X86_TRAP_NMI (a separate event type), X86_TRAP_SPURIOUS
	 * (interrupts are their own event type), and X86_TRAP_OLD_MF
	 * (387 only!).
	 *
	 * These casts are safe, because the FRED handler arguments
	 * is a strict superset of the IRQENTRY arguments.
	 */
	static const fred_handler exception_handlers[X86_NR_HW_TRAPS] = {
		[0 ... X86_NR_HW_TRAPS-1] = fred_bad_event,
		[X86_TRAP_DE] = (fred_handler)exc_divide_error,
		[X86_TRAP_OF] = (fred_handler)exc_overflow,
		[X86_TRAP_BR] = (fred_handler)exc_bounds,
		[X86_TRAP_NM] = (fred_handler)exc_device_not_available,
		[X86_TRAP_MF] = (fred_handler)exc_coprocessor_error,
		[X86_TRAP_XF] = (fred_handler)exc_simd_coprocessor_error,
		[X86_TRAP_TS] = (fred_handler)exc_invalid_tss,
		[X86_TRAP_NP] = (fred_handler)exc_segment_not_present,
		[X86_TRAP_SS] = (fred_handler)exc_stack_segment,
		[X86_TRAP_GP] = (fred_handler)exc_general_protection,
		[X86_TRAP_AC] = (fred_handler)exc_alignment_check,
		[X86_TRAP_UD] = (fred_handler)exc_invalid_op,
		[X86_TRAP_BP] = (fred_handler)exc_int3,
		[X86_TRAP_PF] = fred_exc_page_fault,
#ifdef CONFIG_X86_MCE
		[X86_TRAP_MC] = (fred_handler)exc_machine_check,
#endif
		[X86_TRAP_DB] = fred_exc_debug,
		[X86_TRAP_DF] = (fred_handler)exc_double_fault,
#ifdef CONFIG_AMD_MEM_ENCRYPT
		[X86_TRAP_VC] = (fred_handler)exc_vmm_communication,
#endif
	};

	if (likely(vector < X86_NR_HW_TRAPS)) {
		vector = array_index_nospec(vector, X86_NR_HW_TRAPS);
		exception_handlers[vector](regs, error_code, vector);
	} else {
		fred_bad_event(regs, error_code, vector);
	}
}

/*
 * Hardware interrupts. Until/unless common_interrupt() can be
 * taught to deal with the special system vectors, split the
 * dispatch. Note: common_interrupt() already deals with
 * IRQ_MOVE_CLEANUP_VECTOR.
 */
DEFINE_FRED_HANDLER(fred_hw_interrupt)
{
	unsigned int sysvec = vector - FIRST_SYSTEM_VECTOR;

	if (sysvec >= NR_SYSTEM_VECTORS) {
		common_interrupt(regs, vector);
	} else {
		sysvec = array_index_nospec(sysvec, NR_SYSTEM_VECTORS);
		fred_system_vector_table[sysvec](regs, error_code, vector);
	}
}

/*
 * Badness...
 */
DEFINE_FRED_HANDLER(fred_bad_event)
{
	const struct fred_info * const fi = fred_info(regs);

	pr_emerg("PANIC: event type %u vec %u err 0x%x aux 0x%lx at %04x:%016lx\n",
		 fi->type, vector, error_code, fi->aux,
		 regs->cs, regs->ip);
	die("invalid or fatal FRED event", regs, error_code);
}

/*
 * Initialize FRED on this CPU. This cannot be __init as it is called
 * during CPU hotplug.
 */
void cpu_init_fred_exceptions(void)
{
	pr_debug("--- cpu_init_fred_exceptions on CPU %d\n", smp_processor_id());

	wrmsrl(MSR_IA32_FRED_CONFIG,
	       FRED_CONFIG_ENTRYPOINT(fred_entrypoint_user) |
	       FRED_CONFIG_REDZONE(8) | /* Reserve for CALL emulation */
	       FRED_CONFIG_INT_STKLVL(0));

	wrmsrl(MSR_IA32_FRED_STKLVLS,
	       FRED_STKLVL(X86_TRAP_NMI, 2) |
	       FRED_STKLVL(X86_TRAP_MC,  2) |
	       FRED_STKLVL(X86_TRAP_DF,  3));

	/* The FRED equivalents to IST stacks... */
	wrmsrl(MSR_IA32_FRED_RSP1, __this_cpu_ist_top_va(DB));
	wrmsrl(MSR_IA32_FRED_RSP2, __this_cpu_ist_top_va(NMI));
	wrmsrl(MSR_IA32_FRED_RSP3, __this_cpu_ist_top_va(DF));

	/* Not used with FRED */
	wrmsrl(MSR_LSTAR, 0ULL);
	wrmsrl(MSR_CSTAR, 0ULL);
	wrmsrl_safe(MSR_IA32_SYSENTER_CS,  (u64)GDT_ENTRY_INVALID_SEG);
	wrmsrl_safe(MSR_IA32_SYSENTER_ESP, 0ULL);
	wrmsrl_safe(MSR_IA32_SYSENTER_EIP, 0ULL);

	/* Enable FRED */
	cr4_set_bits(X86_CR4_FRED);
	idt_invalidate();	/* Any further IDT use is a bug */

	/* Use int $0x80 for 32-bit system calls in FRED mode */
	setup_clear_cpu_cap(X86_FEATURE_SYSENTER32);
	setup_clear_cpu_cap(X86_FEATURE_SYSCALL32);
}

/*
 * Initialize system vectors from a FRED perspective, so
 * lapic_assign_system_vectors() can do its job.
 */
void __init fred_setup_apic(void)
{
	int i;

	for (i = 0; i < FIRST_EXTERNAL_VECTOR; i++)
		set_bit(i, system_vectors);

	/*
	 * Don't set the non assigned system vectors in the
	 * system_vectors bitmap. Otherwise they show up in
	 * /proc/interrupts.
	 */
#ifdef CONFIG_SMP
	set_bit(IRQ_MOVE_CLEANUP_VECTOR, system_vectors);
#endif

	for (i = 0; i < NR_SYSTEM_VECTORS; i++) {
		if (fred_system_vector_table[i] !=
		    (fred_handler)spurious_interrupt) {
			set_bit(i + FIRST_SYSTEM_VECTOR, system_vectors);
		}
	}

	/* The rest are fair game... */
}
