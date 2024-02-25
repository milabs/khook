#include "../internal.h"

#ifdef __i686__

#define kernel_write_enter() asm volatile (	\
	"cli\n\t"				\
	"mov %%cr0, %%eax\n\t"			\
	"and $0xfffeffff, %%eax\n\t"		\
	"mov %%eax, %%cr0\n\t"			\
	::: "%eax" )

#define kernel_write_leave() asm volatile (	\
	"mov %%cr0, %%eax\n\t"			\
	"or $0x00010000, %%eax\n\t"		\
	"mov %%eax, %%cr0\n\t"			\
	"sti\n\t"				\
	::: "%eax" )

#else

#define kernel_write_enter() asm volatile (	\
	"cli\n\t"				\
	"mov %%cr0, %%rax\n\t"			\
	"and $0xfffffffffffeffff, %%rax\n\t"	\
	"mov %%rax, %%cr0\n\t"			\
	::: "%rax" )

#define kernel_write_leave() asm volatile (	\
	"mov %%cr0, %%rax\n\t"			\
	"or $0x0000000000010000, %%rax\n\t"	\
	"mov %%rax, %%cr0\n\t"			\
	"sti\n\t"				\
	::: "%rax" )

#endif

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
	long res = 0;

	kernel_write_enter();
	res = fn(arg);
	kernel_write_leave();

	return res;
}

void khook_arch_sm_init_one(khook_t *hook) {
	if (hook->target.addr[0] == (char)0xE9 ||
	    hook->target.addr[0] == (char)0xCC) return;

	while (hook->nbytes < 5) {
		hook->nbytes += khook_arch_lde_get_length(hook->target.addr + hook->nbytes);
	}

	kernel_write_enter();
	khook_arch_create_stub(hook);
	khook_arch_create_orig(hook);
	x86_put_jmp(hook->target.addr, hook->target.addr, hook->stub); // activate
	kernel_write_leave();
}

void khook_arch_sm_cleanup_one(khook_t *hook) {
	kernel_write_enter();
	memcpy(hook->target.addr, hook->orig, hook->nbytes); // deactivate
	kernel_write_leave();
}

long khook_arch_init(void) {
	return khook_arch_lde_init();
}
