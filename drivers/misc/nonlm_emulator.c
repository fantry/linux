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

/*
 * each CPU should have its own context for emulator to execute.
 */

static void emulate(void)
{
	unsigned long ap_start_addr;
	unsigned long cr3;

	asm volatile("vmcall"
		     : "=a"(ap_start_addr)
		     : "a"(13), "b"(1)
		     : "memory");
	pr_info("AP starting from 0x%lx\n", ap_start_addr);

	hv_log_ulong(l4e_va);

	asm volatile("mov %%cr3,%0" : "=r" (cr3) : __FORCE_ORDER);
	hv_log_ulong(cr3);

	cr3 = __pa(l4e_va) | (cr3 & 0xfff);
	asm volatile("mov %0,%%cr3" : : "r" (cr3) : "memory");
	asm volatile("vmcall"
		     : : "a"(13), "b"(3), "c"((unsigned long)cr3)
		     : "memory");
	hv_log_ulong(0);

	pr_info("AP bring up instruction dump:\n");
	for (int i = 0; i < 8; i++) {
		unsigned char *x = (unsigned char *)ap_start_addr + 16 * i;
		pr_info("\t\t%02x %02x %02x %02x %02x %02x %02x %02x"
			"    %02x %02x %02x %02x %02x %02x %02x %02x\n",
			x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7],
			x[8], x[9], x[10], x[11], x[12], x[13], x[14], x[15]);
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
