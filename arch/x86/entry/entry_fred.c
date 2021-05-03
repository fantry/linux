/* SPDX-License-Identifier: GPL-2.0 */
/*
 * arch/x86/entry/entry_fred.c
 *
 * This contains the dispatch functions called from the entry point
 * assembly. These need to be in a separate file from the
 * handler functions, as zap_registers() need %rbp to be a global
 * register to be able to do its job, but that also means that this
 * file *must* be compiled with -fomit-frame-pointer.
 */

#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/nospec.h>
#include <asm/frame.h>
#include <asm/fred.h>
#include <asm/ptrace.h>
#include <asm/syscall.h>

/*
 * Caller-saved registers as global register variables so we can
 * force them to zero without gcc trying to preserve them.
 */
register unsigned long rbx asm("%rbx");
register unsigned long rbp asm("%rbp");
register unsigned long r12 asm("%r12");
register unsigned long r13 asm("%r13");
register unsigned long r14 asm("%r14");
register unsigned long r15 asm("%r15");

/*
 * For extra speed, this is held with the entry value, as does the
 * legacy entry code. It is also typically the first choice for a
 * register for gcc to clobber.
 */
register unsigned long rax asm("%rax");

#define zap_register(x)						\
	do {							\
		register long x asm("%" #x) = 0;		\
		asm volatile("" : : "r" (x));			\
	} while (0)

static __always_inline void zap_registers(struct pt_regs *regs)
{
	/* Saved registers */
	rbp = encode_frame_pointer(regs);
	rbx = 0;
	r12 = 0;
	r13 = 0;
	r14 = 0;
	r15 = 0;

	/* Clobbered registers */
	zap_register(rcx);
	zap_register(rdx);
	zap_register(rsi);
	zap_register(r8);
	zap_register(r9);
	zap_register(r10);
	zap_register(r11);

	barrier();
}

__visible noinstr void fred_entry_from_user(struct pt_regs *regs)
{
	static const fred_handler user_handlers[FRED_EXTYPE_COUNT] =
	{
		[EXTYPE_HWINT]    = fred_hw_interrupt,
		[EXTYPE_RESERVED] = fred_bad_event,
		[EXTYPE_NMI]      = fred_exc_nmi,
		[EXTYPE_SWINT]    = fred_sw_interrupt_user,
		[EXTYPE_HWFAULT]  = fred_exception,
		[EXTYPE_SWFAULT]  = fred_exception,
		[EXTYPE_PRIVSW]   = fred_exception,
		[EXTYPE_SYSCALL]  = fred_syscall_slow
	};
	const struct fred_info * const fi = fred_info(regs);

	zap_registers(regs);

	/* The pt_regs frame on entry here is correct for a system call. */

	if (likely(fi->type == EXTYPE_SYSCALL &&
		   fi->vector == FRED_SYSCALL)) {
		do_syscall_64(regs, rax);
	} else if (likely(IS_ENABLED(CONFIG_IA32_EMULATION) &&
			  fi->type == EXTYPE_SWINT &&
			  fi->vector == IA32_SYSCALL_VECTOR)) {
		do_int80_syscall_32(regs); /* + rax? */
	} else {
		/* Not a system call */
		unsigned int errcode, vector, type;

		/* Convert frame to an exception frame */
		regs->ax = rax;
		regs->orig_ax = -1;

		errcode = fi->errcode;
		vector  = fi->vector;
		type    = fi->type;

		type = array_index_nospec(type, FRED_EXTYPE_COUNT);
		user_handlers[type](regs, errcode, vector);
	}
}

__visible noinstr void fred_entry_from_kernel(struct pt_regs *regs)
{
	static const fred_handler kernel_handlers[FRED_EXTYPE_COUNT] =
	{
		[EXTYPE_HWINT]    = fred_hw_interrupt,
		[EXTYPE_RESERVED] = fred_bad_event,
		[EXTYPE_NMI]      = fred_exc_nmi,
		[EXTYPE_SWINT]    = fred_bad_event,
		[EXTYPE_HWFAULT]  = fred_exception,
		[EXTYPE_SWFAULT]  = fred_exception,
		[EXTYPE_PRIVSW]   = fred_exception,
		[EXTYPE_SYSCALL]  = fred_bad_event
	};

	unsigned int errcode, vector, type;
	const struct fred_info *fi = fred_info(regs);

	zap_registers(regs);

	/* The pt_regs frame on entry here is an exception frame */

	errcode = fi->errcode;
	vector  = fi->vector;
	type    = fi->type;

	type = array_index_nospec(type, FRED_EXTYPE_COUNT);
	kernel_handlers[type](regs, errcode, vector);
}
