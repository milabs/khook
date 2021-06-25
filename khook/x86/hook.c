#include "../internal.h"

#define ASM_CLI asm volatile ("cli\n\t" ::: )
#define ASM_STI asm volatile ("sti\n\t" ::: )

#ifdef USE_CR0_FAM
# define kernel_write_enter() asm volatile (	\
	"cli\n\t"				\
	"mov %%cr0, %%rax\n\t"			\
	"and $0xfffffffffffeffff, %%rax\n\t"	\
	"mov %%rax, %%cr0\n\t"			\
	::: "%rax" )

# define kernel_write_leave() asm volatile (	\
	"mov %%cr0, %%rax\n\t"			\
	"or $0x0000000000010000, %%rax\n\t"	\
	"mov %%rax, %%cr0\n\t"			\
	"sti\n\t"				\
	::: "%rax" )
#endif
#ifdef USE_PTE_FAM
/*|PTE FAMILY|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*/
/*|*/static void set_addr_rw(volatile void *addr){
/*|*/   unsigned int level;
/*|*/   uint64_t *pte = NULL;
/*|*/	pte = (uint64_t*)lookup_address((unsigned long)addr, &level);
/*|*/   if (pte[0x00] & ~((unsigned long long int)1<<1))
/*|*/		pte[0x00] |= ((unsigned long long int)1<<1);
/*|*/}
/*|*/static void set_addr_ro(volatile void *addr){
/*|*/   unsigned int level;
/*|*/   uint64_t *pte = NULL;
/*|*/	pte = (uint64_t*)lookup_address((unsigned long)addr, &level);
/*|*/   pte[0x00] = pte[0x00] & ~((unsigned long long int)1<<1);
/*|*/}
/*|*/static void set_addr_ex(volatile uint64_t addr){
/*|*/   unsigned int level;
/*|*/   uint64_t *pte = NULL;
/*|*/	pte = (uint64_t*)lookup_address((unsigned long)addr, &level);
/*|*/   if (pte[0x00] & ((unsigned long long int)1<<63))
/*|*/           pte[0x00] ^= ((unsigned long long int)1<<63);
/*|*/   __asm__("cpuid  \n\t");
/*|*/}
/*|*/static void set_addr_nx(volatile void *addr){
/*|*/   unsigned int level;
/*|*/   uint64_t *pte = NULL;
/*|*/	pte = (uint64_t*)lookup_address((unsigned long)addr, &level);
/*|*/   if ( !(pte[0x00] & ((unsigned long long int)1<<63)))
/*|*/           pte[0x00] ^= ((unsigned long long int)1<<63);
/*|*/   __asm__("cpuid  \n\t");
/*|*/}
/*|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*/
////////////////////////////////////////////////////////////////////////////////
// IN-kernel length disassembler engine (x86 only, 2.6.33+)
////////////////////////////////////////////////////////////////////////////////
#endif

#ifndef USE_CR0_FAM
# ifndef USE_PTE_FAM
#  error "At least one FAM *must* be used..."
# endif
#endif

#include <asm/insn.h>

static struct {
	typeof(insn_init) *init;
	typeof(insn_get_length) *get_length;
} khook_arch_lde;

static inline int khook_arch_lde_init(void) {
	khook_arch_lde.init = (void *)khook_lookup_name("insn_init");
	if (!khook_arch_lde.init) {
		printk("khook: can't find insn_init symbol\n");
		return -EINVAL;
	}
	khook_arch_lde.get_length = (void *)khook_lookup_name("insn_get_length");
	if (!khook_arch_lde.get_length) {
		printk("khook: can't find insn_get_length symbol\n");
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
static inline void x86_put_jmp(void *a, void *f, void *t)
{
	*((char *)(a + 0)) = 0xE9;
	*(( int *)(a + 1)) = (long)(t - (f + 5));
}

static const char khook_stub_template[] = {
# include KHOOK_STUB_FILE_NAME
};

static inline void stub_fixup(void *stub, const void *value) {
	while (*(int *)stub != 0xcacacaca) stub++;
	*(long *)stub = (long)value;
}

static inline void khook_arch_sm_init_one(khook_t *hook) {
	khook_stub_t *stub = KHOOK_STUB(hook);
	if (hook->target.addr[0] == (char)0xE9 ||
	    hook->target.addr[0] == (char)0xCC) return;

	BUILD_BUG_ON(sizeof(khook_stub_template) > offsetof(khook_stub_t, nbytes));
	memcpy(stub, khook_stub_template, sizeof(khook_stub_template));
	stub_fixup(stub->hook, hook->fn);

	while (stub->nbytes < 5)
		stub->nbytes += khook_arch_lde_get_length(hook->target.addr + stub->nbytes);

	memcpy(stub->orig, hook->target.addr, stub->nbytes);
	x86_put_jmp(stub->orig + stub->nbytes, stub->orig + stub->nbytes, hook->target.addr + stub->nbytes);

ASM_CLI;
#ifdef USE_CR0_FAM
	kernel_write_enter();
#endif
#ifdef USE_PTE_FAM
	set_addr_rw( hook->target.addr );
#endif

	if (hook->flags & KHOOK_F_NOREF) {
		x86_put_jmp(hook->target.addr, hook->target.addr, hook->fn);
	} else {
		x86_put_jmp(hook->target.addr, hook->target.addr, stub->hook);
	}

#ifdef USE_PTE_FAM
        set_addr_ro( hook->target.addr );
#endif
#ifdef USE_CR0_FAM
        kernel_write_leave();
#endif
ASM_STI;

	hook->orig = stub->orig; // the only link from hook to stub
}

static inline void khook_arch_sm_cleanup_one(khook_t *hook) {
	khook_stub_t *stub = KHOOK_STUB(hook);
ASM_CLI;
#ifdef USE_CR0_FAM
        kernel_write_enter();
#endif
#ifdef USE_PTE_FAM
        set_addr_rw( hook->target.addr );
#endif
	memcpy(hook->target.addr, stub->orig, stub->nbytes);
#ifdef USE_PTE_FAM
        set_addr_ro( hook->target.addr );
#endif
#ifdef USE_CR0_FAM
        kernel_write_leave();
#endif
ASM_STI;
} /* Maybe, it will be better, if define two wrappers around both FAM's enter/leave ? */

#define KHOOK_ARCH_INIT(...)					\
	(khook_arch_lde_init())
