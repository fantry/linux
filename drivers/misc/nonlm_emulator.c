#include <uapi/asm/processor-flags.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Xin Li");

static struct page *page;
static void *l4e_va;

#define hv_log_ulong(l)							\
	asm volatile("vmcall"						\
		     : : "a"(13), "b"(2), "c"((unsigned long)(l))	\
		     : "memory");

#define PREFIX_DATA	0x08

struct nonlm_desc_ptr {
	unsigned short size;
	unsigned int address;
} __attribute__((packed));

struct nonlm_emulate_ctxt {
	enum {
		REAL_MODE,
		PROTECTED_MODE_32,
	} cpu_mode;

	unsigned int eflags;
	int eip;
	union {
		unsigned int gregs[8];
		struct {
			unsigned int eax;
			unsigned int ecx;
			unsigned int edx;
			unsigned int ebx;
			unsigned int ebp;
			unsigned int esp;
			unsigned int esi;
			unsigned int edi;
		};
	};
	union {
		unsigned short sregs[6];
		struct {
			unsigned short es;
			unsigned short cs;
			unsigned short ss;
			unsigned short ds;
			unsigned short fs;
			unsigned short gs;
		};
	};
	struct nonlm_desc_ptr gdtr;
	struct nonlm_desc_ptr idtr;
	union {
		unsigned int crs[5];
		struct {
			unsigned int cr0;
			unsigned int cr1;
			unsigned int cr2;
			unsigned int cr3;
			unsigned int cr4;
		};
	};
	unsigned long efer;
};

/*
 * each CPU should have its own context for emulator to execute.
 */

static inline unsigned int get_greg(struct nonlm_emulate_ctxt *cpu_ctxt, unsigned char reg)
{
	return cpu_ctxt->gregs[reg];
}

static inline void *get_greg_addr(struct nonlm_emulate_ctxt *cpu_ctxt, unsigned char reg)
{
	return &cpu_ctxt->gregs[reg];
}

static inline unsigned short get_sreg(struct nonlm_emulate_ctxt *cpu_ctxt, unsigned char reg)
{
	return cpu_ctxt->sregs[reg];
}

static inline unsigned short *get_sreg_addr(struct nonlm_emulate_ctxt *cpu_ctxt, unsigned char reg)
{
	return &cpu_ctxt->sregs[reg];
}

static inline unsigned int get_creg(struct nonlm_emulate_ctxt *cpu_ctxt, unsigned char reg)
{
	return cpu_ctxt->crs[reg];
}

static inline unsigned int *get_creg_addr(struct nonlm_emulate_ctxt *cpu_ctxt, unsigned char reg)
{
	return &cpu_ctxt->crs[reg];
}

static void emulate(void) // where is my stack? should get from memory allocated in init
{
	struct nonlm_emulate_ctxt cpu_ctxt;
	unsigned long ap_start_vector;
	unsigned long cr3;
	int instr_emulated = -1;
	unsigned int prefixes;
	int instr_len = 0;
	unsigned char b, *instr_start;

	asm volatile("vmcall"
		     : "=a"(ap_start_vector)
		     : "a"(13), "b"(1)
		     : "memory");
	pr_info("AP starting from 0x%lx\n", ap_start_vector);

	hv_log_ulong(l4e_va);

	asm volatile("mov %%cr3,%0" : "=r" (cr3) : __FORCE_ORDER);
	hv_log_ulong(cr3);

	cr3 = __pa(l4e_va) | (cr3 & 0xfff);
	asm volatile("mov %0,%%cr3" : : "r" (cr3) : "memory");
	asm volatile("vmcall"
		     : : "a"(13), "b"(3), "c"((unsigned long)cr3)
		     : "memory");
	hv_log_ulong(0);

	pr_info("AP bring up instruction dump @0x%lx:\n", ap_start_vector << 12);
	for (int i = 0; i < 8; i++) {
		unsigned char *x = (unsigned char *)(ap_start_vector << 12)  + 16 * i;
		pr_info("\t\t%02x %02x %02x %02x %02x %02x %02x %02x"
			"    %02x %02x %02x %02x %02x %02x %02x %02x\n",
			x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7],
			x[8], x[9], x[10], x[11], x[12], x[13], x[14], x[15]);
	}

	pr_info("AP bring up instruction dump @0x%x:\n", 0x97ff0);
	for (int i = 0; i < 8; i++) {
		unsigned char *x = (unsigned char *)(0x97ff0)  + 16 * i;
		pr_info("\t\t%02x %02x %02x %02x %02x %02x %02x %02x"
			"    %02x %02x %02x %02x %02x %02x %02x %02x\n",
			x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7],
			x[8], x[9], x[10], x[11], x[12], x[13], x[14], x[15]);
	}

	memset(&cpu_ctxt, 0, sizeof(struct nonlm_emulate_ctxt));
	cpu_ctxt.cs = ap_start_vector << 8;

next_instr:
	prefixes = 0;
	instr_emulated++;
	cpu_ctxt.eip += instr_len;
	if (cpu_ctxt.cpu_mode == REAL_MODE)
		instr_start = (unsigned char *)((unsigned long)(cpu_ctxt.cs << 4) + cpu_ctxt.eip);
	else
		instr_start = (unsigned char *)(unsigned long)cpu_ctxt.eip;
	pr_info("emulate instruction @ 0x%lx\n", (unsigned long)instr_start);
	instr_len = 0;

next_byte:
	// XXX: should check if instr_start + instr_len is still within code segment.
	b = *(instr_start + instr_len++);

	switch (b) {
	case 0x0f:
		switch (*(instr_start + instr_len++)) {
		case 0x01: { // lgdt/lidt
			unsigned char modrm = *(instr_start + instr_len++);
			unsigned char reg = (modrm >> 3) & 7;
			unsigned char mod = (modrm >> 6) & 3;
			unsigned long disp16 = 0;
			struct nonlm_desc_ptr *dtr;
			if (mod == 0 && ((modrm & 7) == 6)) {
				disp16 = *(short *)(instr_start + instr_len);
				instr_len += 2;
				disp16 += cpu_ctxt.ds << 4;
			} else {
				pr_err("unrecognized instruction 0x%02x\n", b);
				break;
			}
			if (reg == 2) {
				dtr = &cpu_ctxt.gdtr;
				pr_info("lgdt from 0x%lx\n", disp16);
			}
			if (reg == 3) {
				dtr = &cpu_ctxt.idtr;
				pr_info("lidt from 0x%lx\n", disp16);
			}
			dtr->size = *(unsigned short *)(unsigned long)disp16;
			pr_info("size 0x%x\n", dtr->size);
			if (cpu_ctxt.cpu_mode == REAL_MODE && prefixes & PREFIX_DATA) {
				dtr->address = *(unsigned int *)(unsigned long)(disp16 + 2);
				pr_info("address 0x%x\n", dtr->address);
			} else {
				pr_err("unrecognized instruction 0x%02x\n", b);
				break;
			}
			goto next_instr;
		}
		case 0x09: // wbinvd
			pr_info("wbinvd\n");
			goto next_instr;
		case 0x22: { // mov greg ==> cr
			unsigned char modrm = *(instr_start + instr_len++);
			unsigned char reg = (modrm >> 3) & 7;
			unsigned char mod = (modrm >> 6) & 3;
			if (mod == 3) {
				unsigned int *dst = get_creg_addr(&cpu_ctxt, reg);
				*dst = get_greg(&cpu_ctxt, modrm & 0x7);
				pr_info("mov to cr%d: 0x%x\n", reg, get_creg(&cpu_ctxt, reg));
			} else {
				pr_err("unrecognized instruction 0x%02x\n", b);
				break;
			}
			goto next_instr;
		}
		case 0x30: { // wrmsr
			if (cpu_ctxt.ecx == MSR_EFER) {
				cpu_ctxt.efer = (unsigned long)cpu_ctxt.edx << 32 | cpu_ctxt.eax;
				pr_info("wrmsr 0x%x: 0x%x : 0x%x ==> 0x%lx\n",
					cpu_ctxt.ecx, cpu_ctxt.eax, cpu_ctxt.edx, cpu_ctxt.efer);
			} else {
				pr_err("unrecognized MSR 0x%x\n", cpu_ctxt.ecx);
			}
			goto next_instr;
		}
		case 0x32: { // rdmsr
			if (cpu_ctxt.ecx == MSR_EFER) {
				cpu_ctxt.eax = (unsigned int)cpu_ctxt.efer;
				cpu_ctxt.edx = (unsigned int)(cpu_ctxt.efer >> 32);
				pr_info("rdmsr 0x%x: 0x%lx ==> 0x%x : 0x%x\n",
					cpu_ctxt.ecx, cpu_ctxt.efer, cpu_ctxt.eax, cpu_ctxt.edx);
			} else {
				pr_err("unrecognized MSR 0x%x\n", cpu_ctxt.ecx);
			}
			goto next_instr;
		}
		case 0xba: { // bt
			unsigned char modrm = *(instr_start + instr_len++);
			unsigned char reg = (modrm >> 3) & 7;
			unsigned char mod = (modrm >> 6) & 3;
			if (mod == 0 && reg == 4 && (modrm & 7) == 5) {
				int disp32 = *(int *)(instr_start + instr_len);
				int value = *(int *)(unsigned long)disp32;
				unsigned char bit_offset;
				instr_len += 4;
				bit_offset = *(unsigned char *)(instr_start + instr_len);
				if (value & (1 << bit_offset))
					cpu_ctxt.eflags |= X86_EFLAGS_CF;
				else
					cpu_ctxt.eflags &= ~X86_EFLAGS_CF;
				instr_len++;
				pr_info("bt: 0x%x @ 0x%x, offset 0x%x\n", value, disp32, bit_offset);
			} else {
				pr_err("unrecognized instruction 0x%02x\n", b);
				break;
			}
			goto next_instr;
		}
		default:
			pr_err("unrecognized instruction 0x%02x\n", b);
		}
		break;
	case 0x3b: { // cmp
		unsigned char modrm = *(instr_start + instr_len++);
		unsigned char reg = (modrm >> 3) & 7;
		unsigned char mod = (modrm >> 6) & 3;
		if (mod == 0 && (modrm & 7) == 5) {
			int greg = get_greg(&cpu_ctxt, reg);
			unsigned int moffset = *(unsigned int *)(instr_start + instr_len);
			int m = *(int *)(unsigned long)moffset;
			int r = greg - m;
			if (r == 0)
				cpu_ctxt.eflags |= X86_EFLAGS_ZF;
			else
				cpu_ctxt.eflags &= ~X86_EFLAGS_ZF;
			instr_len += 4;
			pr_info("cmp: 0x%x @ 0x%x with greg%d 0x%x\n", m, moffset, reg, greg);
		}
		goto next_instr;
	}
	case 0x66:
		prefixes |= PREFIX_DATA;
		goto next_byte;
	case 0x73: // jae
		if (cpu_ctxt.eflags & X86_EFLAGS_CF) {
			instr_len++;
		} else {
			char offset = *(char *)(instr_start + instr_len);
			instr_len++;
			instr_len += offset;
		}
		pr_info("jae\n");
		goto next_instr;
	case 0x74: { // je
		char offset = *(char *)(instr_start + instr_len++);
		if (cpu_ctxt.eflags & X86_EFLAGS_ZF)
			instr_len += offset;
		pr_info("je\n");
		goto next_instr;
	}
	case 0x75: { // jne
		char offset = *(char *)(instr_start + instr_len++);
		if (!(cpu_ctxt.eflags & X86_EFLAGS_ZF))
			instr_len += offset;
		pr_info("jne\n");
		goto next_instr;
	}
	case 0x81: { // add
		unsigned char modrm = *(instr_start + instr_len++);
		unsigned char mod = (modrm >> 6) & 3;
		if (mod == 3) {
			int imm32 = *(int *)(instr_start + instr_len);
			int *dst = get_greg_addr(&cpu_ctxt, modrm & 0x7);
			*dst += imm32;
			instr_len += 4;
			pr_info("add %x to reg%d: %x\n", imm32, modrm & 0x7, get_greg(&cpu_ctxt, modrm & 0x7));
		} else {
			pr_err("unrecognized instruction 0x%02x\n", b);
			break;
		}
		goto next_instr;
	}
	case 0x85: { // test reg, reg
		unsigned char modrm = *(instr_start + instr_len++);
		unsigned char reg = (modrm >> 3) & 7;
		unsigned char mod = (modrm >> 6) & 3;
		if (mod != 3) {
			pr_err("unrecognized instruction 0x%02x\n", b);
			break;
		}
		cpu_ctxt.eflags &= ~X86_EFLAGS_CF;
		cpu_ctxt.eflags &= ~X86_EFLAGS_OF;
		if ((cpu_ctxt.cpu_mode == REAL_MODE && prefixes & PREFIX_DATA) ||
		    cpu_ctxt.cpu_mode == PROTECTED_MODE_32) {
			unsigned int a = get_greg(&cpu_ctxt, modrm & 0x7);
			unsigned int b = get_greg(&cpu_ctxt, reg);
			unsigned int r = a & b;
			if (r == 0)
				cpu_ctxt.eflags |= X86_EFLAGS_ZF;
			else
				cpu_ctxt.eflags &= ~X86_EFLAGS_ZF;
			if (r & 0x80000000)
				cpu_ctxt.eflags |= X86_EFLAGS_SF;
			else
				cpu_ctxt.eflags &= ~X86_EFLAGS_SF;
			pr_info("test 0x%x : 0x%x\n", a, b);
		} else if ((cpu_ctxt.cpu_mode == PROTECTED_MODE_32 && prefixes & PREFIX_DATA) ||
		    cpu_ctxt.cpu_mode == REAL_MODE) {
			unsigned short a = get_greg(&cpu_ctxt, modrm & 0x7);
			unsigned short b = get_greg(&cpu_ctxt, reg);
			unsigned short r = a & b;
			if (r == 0)
				cpu_ctxt.eflags |= X86_EFLAGS_ZF;
			else
				cpu_ctxt.eflags &= ~X86_EFLAGS_ZF;
			if (r & 0x8000)
				cpu_ctxt.eflags |= X86_EFLAGS_SF;
			else
				cpu_ctxt.eflags &= ~X86_EFLAGS_SF;
			pr_info("test 0x%x : 0x%x\n", a, b);
		}
		goto next_instr;
	}
	case 0x8b: { // mov [moffset] ==> greg
		unsigned char modrm = *(instr_start + instr_len++);
		unsigned char reg = (modrm >> 3) & 7;
		unsigned char mod = (modrm >> 6) & 3;
		if (mod == 0 && (modrm & 7) == 5) {
			unsigned int *dst = get_greg_addr(&cpu_ctxt, reg);
			unsigned int moffset = *(unsigned int *)(instr_start + instr_len);
			pr_info("before mov [%x] ==> greg%d %x\n", moffset, reg, cpu_ctxt.gregs[reg]);
			*dst = *(unsigned int *)(unsigned long)moffset;
			pr_info("after mov [%x] ==> greg%d %x\n", moffset, reg, cpu_ctxt.gregs[reg]);
			instr_len += 4;
		} else {
			pr_err("unrecognized instruction 0x%02x\n", b);
			break;
		}
		goto next_instr;
	}
	case 0x8c: // mov sreg ==> greg
		if (cpu_ctxt.cpu_mode == REAL_MODE) {
			unsigned char modrm = *(instr_start + instr_len++);
			unsigned char reg = (modrm >> 3) & 7;
			unsigned char mod = (modrm >> 6) & 3;
			if (mod == 3) {
				unsigned short *dst = get_greg_addr(&cpu_ctxt, modrm & 0x7);
				*dst = get_sreg(&cpu_ctxt, reg);
				pr_info("mov sreg ==> greg: 0x%x\n", get_greg(&cpu_ctxt, modrm & 0x7));
			} else {
				pr_err("unrecognized instruction 0x%02x\n", b);
				break;
			}
		} else {
			pr_err("unrecognized instruction 0x%02x\n", b);
			break;
		}
		goto next_instr;
	case 0x8e: { // mov greg ==> sreg
		unsigned char modrm = *(instr_start + instr_len++);
		unsigned char reg = (modrm >> 3) & 7;
		unsigned char mod = (modrm >> 6) & 3;
		if (mod == 3) {
			unsigned short *dst = get_sreg_addr(&cpu_ctxt, reg);
			*dst = (unsigned short)get_greg(&cpu_ctxt, modrm & 0x7);
			pr_info("mov greg ==> sreg%d: 0x%x\n", reg, get_sreg(&cpu_ctxt, reg));
		} else {
			pr_err("unrecognized instruction 0x%02x\n", b);
			break;
		}
		goto next_instr;
	}
	case 0xa1: { // mov [moffset] ==> eax
		unsigned int *dst = get_greg_addr(&cpu_ctxt, 0);
		unsigned int moffset = *(unsigned int *)(instr_start + instr_len);
		pr_info("before mov [%x] ==> eax %x\n", moffset, cpu_ctxt.eax);
		*dst = *(unsigned int *)(unsigned long)moffset;
		pr_info("after mov [%x] ==> eax %x\n", moffset, cpu_ctxt.eax);
		instr_len += 4;
		goto next_instr;
	}
	case 0xb8 ... 0xbf: // 0xb8 | greg
		if ((cpu_ctxt.cpu_mode == REAL_MODE && prefixes & PREFIX_DATA) ||
		    cpu_ctxt.cpu_mode == PROTECTED_MODE_32) {
			unsigned int *dst = get_greg_addr(&cpu_ctxt, b & 7);
			*dst = *(unsigned int *)(instr_start + instr_len);
			instr_len += 4;
			pr_info("mov imm ==> greg%d: 0x%x\n", b & 7, get_greg(&cpu_ctxt, b & 7));
		} else if ((cpu_ctxt.cpu_mode == PROTECTED_MODE_32 && prefixes & PREFIX_DATA) ||
		    cpu_ctxt.cpu_mode == REAL_MODE) {
			unsigned short *dst = get_greg_addr(&cpu_ctxt, b & 7);
			*dst = *(unsigned short *)(instr_start + instr_len);
			instr_len += 2;
			pr_info("mov imm ==> greg%d: 0x%x\n", b & 7, get_greg(&cpu_ctxt, b & 7));
		} else {
			pr_err("unrecognized instruction 0x%02x\n", b);
			break;
		}
		goto next_instr;
	case 0xe8: // call
		if (cpu_ctxt.cpu_mode == REAL_MODE) {
			short offset = *(short *)(instr_start + instr_len);
			instr_len += 2;
			//instr_len += offset; // just skip for now
			pr_info("call: 0x%lx\n", (unsigned long)instr_start + instr_len + offset);
			cpu_ctxt.eax = 0; // hack to skip verify_cpu
		} else {
			pr_err("unrecognized instruction 0x%02x\n", b);
			break;
		}
		goto next_instr;
	case 0xea: // ljmp
		if ((cpu_ctxt.cpu_mode == REAL_MODE && prefixes & PREFIX_DATA) ||
		    cpu_ctxt.cpu_mode == PROTECTED_MODE_32) {
			cpu_ctxt.eip = *(unsigned int *)(instr_start + instr_len);
			instr_len += 4;
		} else if ((cpu_ctxt.cpu_mode == PROTECTED_MODE_32 && prefixes & PREFIX_DATA) ||
		    cpu_ctxt.cpu_mode == REAL_MODE) {
			cpu_ctxt.eip = *(unsigned short *)(instr_start + instr_len);
			instr_len += 2;
		}
		cpu_ctxt.cs = *(unsigned short *)(instr_start + instr_len);
		instr_len = 0;
		pr_info("ljmp 0x%04x:0x%08x\n", cpu_ctxt.cs, cpu_ctxt.eip);

		if (cpu_ctxt.cr0 & X86_CR0_PE)
			cpu_ctxt.cpu_mode = PROTECTED_MODE_32;
		if (cpu_ctxt.cr0 & X86_CR0_PE && cpu_ctxt.cr0 & X86_CR0_PG &&
		    cpu_ctxt.cr4 & X86_CR4_PAE && cpu_ctxt.efer & EFER_LME) {
			pr_info("end emulation\n");
		}
		goto next_instr;
	case 0xf4: // halt
		pr_err("unrecognized instruction 0x%02x\n", b);
		break;
	case 0xfa: // cli
		cpu_ctxt.eflags &= ~X86_EFLAGS_IF;
		pr_info("cli\n");
		goto next_instr;
	case 0xfb: // sti
		cpu_ctxt.eflags |= X86_EFLAGS_IF;
		pr_info("sti\n");
		goto next_instr;
	default:
		pr_err("unrecognized instruction 0x%02x\n", b);
		break;
	}
}

static int __init nonlm_emulator_init(void)
{
	unsigned long cr3;
	unsigned long *current_l4e_va;
	void *l3e_va;

	page = __alloc_pages_node(cpu_to_node(0), GFP_ATOMIC, 2);
	if (!page) {
		pr_err("unable to allocate memory\n");
		return -1;
	}

	asm volatile("vmcall"
		     : : "a"(13), "b"(0), "c"((unsigned long)&emulate)
		     : "memory");
	pr_info("emulator loaded @0x%lx\n", (unsigned long)&emulate);

	l4e_va = page_address(page);
	memset(l4e_va, 0, PAGE_SIZE << 2);

	l3e_va = l4e_va + PAGE_SIZE;
	for (unsigned long i = 0; i < 512; i++)
		((unsigned long *)l3e_va)[i] = i << 30 | 0x1a3;
	((unsigned long *)l4e_va)[0] =  __pa(l3e_va) | 0x23;

	asm volatile("mov %%cr3,%0" : "=r" (cr3) : __FORCE_ORDER);
	current_l4e_va = __va(cr3 & 0xfffffffffffff000UL);
	for (unsigned long i = 256; i < 512; i++)
		((unsigned long *)l4e_va)[i] = current_l4e_va[i];

	return 0;
}

static void __exit nonlm_emulator_exit(void)
{
	pr_info("emulator unloaded\n");
}

module_init(nonlm_emulator_init);
module_exit(nonlm_emulator_exit);
