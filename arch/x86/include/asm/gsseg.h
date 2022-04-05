/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_GSSEG_H
#define _ASM_X86_GSSEG_H

#include <linux/types.h>

#include <asm/asm.h>
#include <asm/cpufeature.h>
#include <asm/alternative.h>
#include <asm/processor.h>
#include <asm/nops.h>

#ifdef CONFIG_X86_64

extern asmlinkage void asm_load_gs_index(u16 selector);

#define LKGS_DI	_ASM_BYTES(0xf2,0x0f,0x00,0xf7)

static inline void native_load_gs_index(unsigned int selector)
{
	u16 sel = selector;

	/*
	 * Note: the fixup is used for the LKGS instruction, but
	 * it needs to be attached to the primary instruction sequence
	 * as it isn't something that gets patched.
	 *
	 * %rax is provided to the assembly routine as a scratch
	 * register.
	 */
	alternative_io("1: call asm_load_gs_index\n"
		       "2:\n"
		       ".pushsection \".fixup\",\"ax\"\n"
		       "3:	xorl %k[sel], %k[sel]\n"
		       "	jmp 2b\n"
		       ".popsection\n"
		       _ASM_EXTABLE(1b, 3b),
		       _ASM_BYTES(0x3e) LKGS_DI,
		       X86_FEATURE_LKGS,
		       ASM_OUTPUT2([sel] "+D" (sel), ASM_CALL_CONSTRAINT),
		       ASM_NO_INPUT_CLOBBER(_ASM_AX));
}

#endif /* CONFIG_X86_64 */

#ifndef CONFIG_PARAVIRT_XXL

static inline void load_gs_index(unsigned int selector)
{
#ifdef CONFIG_X86_64
	native_load_gs_index(selector);
#else
	loadsegment(gs, selector);
#endif
}

#endif /* CONFIG_PARAVIRT_XXL */

#endif /* _ASM_X86_GSSEG_H */
