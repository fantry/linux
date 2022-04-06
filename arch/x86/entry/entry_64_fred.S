/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  arch/x86/entry/entry_64_fred.S
 *
 * The actual FRED entry points.
 */
#include <linux/linkage.h>
#include <asm/errno.h>
#include <asm/asm-offsets.h>
#include <asm/fred.h>

#include "calling.h"

	.code64
	.section ".noinstr.text", "ax"

.macro FRED_EXIT
	UNWIND_HINT_REGS
	POP_REGS
	addq $8,%rsp		/* Drop orig_ax */
.endm

	.align 4096

SYM_CODE_START_NOALIGN(fred_entrypoint_user)
        UNWIND_HINT_EMPTY
	/* Stack frame optimized for system calls */
	pushq	%rax		/* orig_ax: system call number */
	PUSH_REGS rax=$-ENOSYS
	movq	%rsp, %rdi	/* %rdi -> pt_regs */
        call	fred_entry_from_user
SYM_INNER_LABEL(fred_exit_user, SYM_L_GLOBAL)
	FRED_EXIT
	ERETU
SYM_CODE_END(fred_entrypoint_user)

	.org fred_entrypoint_user+256
SYM_CODE_START_NOALIGN(fred_entrypoint_kernel)
        UNWIND_HINT_EMPTY
	/* No system calls: exception stack frame */
	pushq	$-1		/* orig_ax: not a system call */
	PUSH_REGS
	movq	%rsp, %rdi	/* %rdi -> pt_regs */
	call	fred_entry_from_kernel
SYM_INNER_LABEL(fred_exit_kernel, SYM_L_GLOBAL)
	FRED_EXIT
	ERETS
SYM_CODE_END(fred_entrypoint_kernel)
