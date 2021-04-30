/* SPDX-License-Identifier: GPL-2.0 */
/*
 * arch/x86/include/asm/fred.h
 *
 * Macros for Fast Return and Exception Delivery
 */

#ifndef ASM_X86_FRED_H
#define ASM_X86_FRED_H

#ifdef CONFIG_X86_FRED

#include <linux/const.h>
#include <asm/asm.h>
#include <asm/irq_vectors.h>

/*
 * Return instructions
 */
#define ERETS			_ASM_BYTES(0xf2,0x0f,0x01,0xca)
#define ERETU			_ASM_BYTES(0xf3,0x0f,0x01,0xca)

/*
 * FRED configuration MSR definitions
 */

/*
 * Exception stack level macro for the FRED_STKLVLS MSR.
 * Usage example: FRED_STKLVL(X86_TRAP_DF, 3)
 * Multiple values can be ORd together.
 */
#define FRED_STKLVL(v,l)	(_AT(unsigned long, l) << (2*(v)))

/* FRED_CONFIG MSR */
#define FRED_CONFIG_CSL_MASK		0x3
#define FRED_CONFIG_SHADOW_STACK_SPACE	_BITUL(3)
#define FRED_CONFIG_REDZONE(b)		__ALIGN_KERNEL_MASK((b), _UL(0x3f))
#define FRED_CONFIG_INT_STKLVL(l)	(_AT(unsigned long, l) << 9)
#define FRED_CONFIG_ENTRYPOINT(p)	_AT(unsigned long, (p))

/*
 * FRED exception information word.
 *
 * Important: the _MASK macros are all zero-based; in other words they
 * expect the field to already be shifted into the right position, if
 * necessary (in many cases a partial load will put it there already.)
 */
#define FRED_EXTYPE_SHIFT	48
#define FRED_EXTYPE_OFFSET	(FRED_EXTYPE_SHIFT >> 3)
#define FRED_EXTYPE_BITS	3
#define FRED_EXTYPE_COUNT	_BITUL(FRED_EXTYPE_BITS)
#define FRED_EXTYPE_MASK	(FRED_EXTYPE_COUNT-1)
#define FRED_VECTOR_SHIFT	32
#define FRED_VECTOR_OFFSET	(FRED_VECTOR_SHIFT >> 3)
#define FRED_VECTOR_BITS	8
#define FRED_VECTOR_COUNT	_BITUL(FRED_VECTOR_BITS)
#define FRED_VECTOR_MASK	(FRED_VECTOR_COUNT-1)
#define FRED_ERRCODE_SHIFT	0
#define FRED_ERRCODE_OFFSET	(FRED_ERRCODE_SHIFT >> 3)
#define FRED_ERRCODE_BITS	16
#define FRED_ERRCODE_COUNT	_BITUL(FRED_ERRCODE_BITS)
#define FRED_ERRCODE_MASK	(FRED_ERRCODE_COUNT-1)

/*
 * Exception type codes: except for EXTYPE_SYSCALL, these are the same
 * that are used by VTx. Unfortunately the INTR_TYPE_ macros in KVM are
 * shifted, so unify later.
 */
#define EXTYPE_HWINT		0	/* Maskable interrupt */
#define EXTYPE_RESERVED		1
#define EXTYPE_NMI		2	/* NMI */
#define EXTYPE_HWFAULT		3	/* Hardware-triggered exceptions */
#define EXTYPE_SWINT		4	/* INT instructions */
#define EXTYPE_PRIVSW		5	/* INT1 (ICEBP) */
#define EXTYPE_SWFAULT		6	/* INT3 (BRKPT), INTO */
#define EXTYPE_SYSCALL		7	/* SYSCALL, SYSENTER */

/* EXTYPE_SYSCALL vector numbers */
#define FRED_SYSCALL		1
#define FRED_SYSENTER		2

/* Flags above the CS selector (regs->csl) */
#define FRED_CSL_ENABLE_NMI		_BITUL(16)
#define FRED_CSL_ALLOW_SINGLE_STEP	_BITUL(17)
#define FRED_CSL_INTERRUPT_SHADOW	_BITUL(18)

#ifndef __ASSEMBLY__

#include <linux/kernel.h>
#include <asm/ptrace.h>

/* FRED stack frame information */
struct fred_info {
	union {
		unsigned long exc; /* Exception info */
		/*
		 * For now, assume the errcode and vector fields
		 * may grow into the reserved area...
		 */
		struct {
			unsigned int errcode : 32;
			unsigned int vector  : 16;
			unsigned int type    :  3;
			unsigned int i_resv1 :  5;
			unsigned int enclv   :  1;
			unsigned int i_resv2 :  7;
		};
	};
	unsigned long aux;	/* Auxiliary data: CR2, DR6, ... */
	unsigned long resv;
};

/* Full format of the FRED stack frame */
struct fred_frame {
	struct pt_regs   regs;
	struct fred_info info;
};

/* Getting the FRED frame information from a pt_regs pointer */
static __always_inline struct fred_info *fred_info(struct pt_regs *regs)
{
	return &container_of(regs, struct fred_frame, regs)->info;
}

/*
 * How FRED event handlers are called. These macros are roughly
 * equivalent to {DEFINE|DECLARE}_IDTENTRY_RAW[_ERRORCODE],
 * but provide a few more arguments.
 */
#define DECLARE_FRED_HANDLER(f) \
	void f (struct pt_regs *regs __maybe_unused, \
		unsigned int error_code __maybe_unused, \
		unsigned int vector __maybe_unused)
#define DEFINE_FRED_HANDLER(f) noinstr DECLARE_FRED_HANDLER(f)
typedef DECLARE_FRED_HANDLER((*fred_handler));

DECLARE_FRED_HANDLER(fred_bad_event);
DECLARE_FRED_HANDLER(fred_syscall_slow);
DECLARE_FRED_HANDLER(fred_exception);
DECLARE_FRED_HANDLER(fred_hw_interrupt);
DECLARE_FRED_HANDLER(fred_sw_interrupt_user);
DECLARE_FRED_HANDLER(fred_sw_interrupt_kernel);

DECLARE_FRED_HANDLER(fred_exc_debug);
DECLARE_FRED_HANDLER(fred_exc_nmi);
DECLARE_FRED_HANDLER(fred_exc_page_fault);

extern const fred_handler fred_system_vector_table[NR_SYSTEM_VECTORS];

#endif /* __ASSEMBLY__ */

#endif /* CONFIG_X86_FRED */

#endif /* ASM_X86_FRED_H */
