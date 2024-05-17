#include "../internal.h"

#ifndef X86_CR0_WP
# define X86_CR0_WP (1UL << 16)
#endif

#ifndef X86_CR4_CET
# define X86_CR4_CET (1UL << 23)
#endif

#ifndef __FORCE_ORDER
# define __FORCE_ORDER "m"(*(unsigned int *)0x1000UL)
#endif

static inline unsigned long x86_read_cr0(void) {
	unsigned long val;
	asm volatile("mov %%cr0, %0\n" : "=r" (val) : __FORCE_ORDER);
	return val;
}

static inline void x86_write_cr0(unsigned long val) {
	asm volatile("mov %0, %%cr0\n": "+r" (val) : : "memory");
}

static inline unsigned long x86_read_cr4(void) {
	unsigned long val;
#ifdef CONFIG_X86_32
	asm volatile("1: mov %%cr4, %0\n"
		     "2:\n"
		     _ASM_EXTABLE(1b, 2b)
		     : "=r" (val) : "0" (0), __FORCE_ORDER);
#else
	asm volatile("mov %%cr4, %0\n" : "=r" (val) : __FORCE_ORDER);
#endif
	return val;
}

static inline void x86_write_cr4(unsigned long val) {
	asm volatile("mov %0, %%cr4\n": "+r" (val) : : "memory");
}

////////////////////////////////////////////////////////////////////////////////
// IN-kernel length disassembler engine (x86 only, 2.6.33+)
////////////////////////////////////////////////////////////////////////////////

#include <asm/insn.h>

static struct {
	typeof(insn_init) *init;
	typeof(insn_get_length) *get_length;
} khook_arch_lde;

static inline int khook_arch_lde_init(void) {
	khook_arch_lde.init = (void *)khook_lookup_name("insn_init");
	if (!khook_arch_lde.init) {
		pr_err("khook: can't find insn_init symbol\n");
		return -EINVAL;
	}
	khook_arch_lde.get_length = (void *)khook_lookup_name("insn_get_length");
	if (!khook_arch_lde.get_length) {
		pr_err("khook: can't find insn_get_length symbol\n");
		return -EINVAL;
	}
	return 0;
}

static inline int khook_arch_lde_get_length(const void *p) {
	struct insn insn;
	int x86_64 = 0;
#ifdef CONFIG_X86_64
	x86_64 = 1;
#endif
#if defined MAX_INSN_SIZE && (MAX_INSN_SIZE == 15) /* 3.19.7+ */
	khook_arch_lde.init(&insn, p, MAX_INSN_SIZE, x86_64);
#else
	khook_arch_lde.init(&insn, p, x86_64);
#endif
	khook_arch_lde.get_length(&insn);
	return insn.length;
}

////////////////////////////////////////////////////////////////////////////////

// place a jump at addr @a from addr @f to addr @t
static inline void x86_put_jmp(void *a, void *f, void *t) {
	*((char *)(a + 0)) = 0xE9;
	*(( int *)(a + 1)) = (long)(t - (f + 5));
}

static inline void khook_arch_create_stub(khook_t *hook) {
	if (!(hook->flags & KHOOK_F_NOREF)) {
		const size_t nbytes = (void *)KHOOK_STUB_hook_end - (void *)KHOOK_STUB_hook;
		memcpy(hook->stub, KHOOK_STUB_hook, nbytes);
	} else {
		const size_t nbytes = (void *)KHOOK_STUB_hook_noref_end - (void *)KHOOK_STUB_hook_noref;
		memcpy(hook->stub, KHOOK_STUB_hook_noref, nbytes);
	}

	//
	// fixup for the @fn address
	//

	if (hook->fn) {
		void *p = hook->stub;
		while (*(int *)p != 0x7a7a7a7a) p++;
		*(long *)p = (long)hook->fn;
	}

	//
	// fixup for the @use_count (twice)
	//
	
	if (!(hook->flags & KHOOK_F_NOREF)) {
		void *p = hook->stub;
#ifdef __x86_64__
		// 1st reference
		while (*(int *)p != 0x7b7b7b7b) p++;
		*(int *)p = (int)((long)&hook->use_count - ((long)p + 4)), p += 4;
		// 2nd reference
		while (*(int *)p != 0x7b7b7b7b) p++;
		*(int *)p = (int)((long)&hook->use_count - ((long)p + 4)), p += 4;
#else
		// 1st reference
		while (*(int *)p != 0x7b7b7b7b) p++;
		*(int *)p = (int)&hook->use_count, p += 4;
		// 2nd reference
		while (*(int *)p != 0x7b7b7b7b) p++;
		*(int *)p = (int)&hook->use_count, p += 4;
#endif
	}
}

static inline void khook_arch_create_orig(khook_t *hook) {
	memcpy(hook->orig, hook->target.addr, hook->nbytes);
	x86_put_jmp(hook->orig + hook->nbytes, hook->orig + hook->nbytes, hook->target.addr + hook->nbytes);
}

////////////////////////////////////////////////////////////////////////////////

long khook_arch_write_kernel(long (* fn)(void *), void *arg) {
	long res = 0, cr0, cr4;

	asm volatile ("cli\n");

	cr0 = x86_read_cr0();
	cr4 = x86_read_cr4();

	if (cr4 & X86_CR4_CET)
		x86_write_cr4(cr4 & ~X86_CR4_CET);
	x86_write_cr0(cr0 & ~X86_CR0_WP);

	res = fn(arg);

	x86_write_cr0(cr0);
	if (cr4 & X86_CR4_CET)
		x86_write_cr4(cr4);

	asm volatile ("sti\n");

	return res;
}

void khook_arch_sm_init_one(khook_t *hook) {
	void _activate(khook_t *hook) {
		khook_arch_create_stub(hook);
		khook_arch_create_orig(hook);
		x86_put_jmp(hook->target.addr, hook->target.addr, hook->stub);
	}

	if (hook->target.addr[0] == (char)0xE9 ||
	    hook->target.addr[0] == (char)0xCC) return;

	while (hook->nbytes < 5) {
		hook->nbytes += khook_arch_lde_get_length(hook->target.addr + hook->nbytes);
	}

	khook_arch_write_kernel((void *)_activate, hook);
}

void khook_arch_sm_cleanup_one(khook_t *hook) {
	void _deactivate(khook_t *hook) {
		memcpy(hook->target.addr, hook->orig, hook->nbytes);
	}

	khook_arch_write_kernel((void *)_deactivate, hook);
}

long khook_arch_init(void) {
	return khook_arch_lde_init();
}
