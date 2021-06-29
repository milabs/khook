#include "../internal.h"

#ifndef ASM_CLI
# define ASM_CLI __asm__("cli\n\t" ::: )
# define ASM_STI __asm__("sti\n\t" ::: )
#endif

#ifndef USE_CR0_FAM
# ifndef USE_PTE_FAM
#  error "At least one FAM *must* be used..."
# endif
#endif

#ifdef USE_CR0_FAM
static volatile int is_cr0_switched = 0x00;
# define kernel_write_enter() do{ asm volatile (\
	"cli\n\t"				\
	"mov %%cr0, %%rax\n\t"			\
	"and $0xfffffffffffeffff, %%rax\n\t"	\
	"mov %%rax, %%cr0\n\t"			\
	::: "%rax" ); is_cr0_switched++;}while(0)
# define kernel_write_leave() do{asm volatile (	\
	"mov %%cr0, %%rax\n\t"			\
	"or $0x0000000000010000, %%rax\n\t"	\
	"mov %%rax, %%cr0\n\t"			\
	"sti\n\t"				\
	::: "%rax" ); is_cr0_switched--;}while(0)
#endif

# define CALLADDR6(x, r1, r2, r3, r4, r5, r6) \
	( (u_int64_t(*)(uint64_t,...)) (x) )( (uint64_t)r1, (uint64_t)r2, (uint64_t)r3, \
		(uint64_t)r4, (uint64_t)r5, (uint64_t)r6 )
# if 0
	pg_level /*  0             1            2            3             4              5     */
enum pg_level {PG_LEVEL_NONE, PG_LEVEL_4K, PG_LEVEL_2M, PG_LEVEL_1G, PG_LEVEL_512G, PG_LEVEL_NUM};
# endif

#ifdef USE_PTE_FAM
/* The Teamlead say *NO* (unsigned long long int)1<<1 in the code, only flag names */
# ifndef PTE_PAGE_BIT_RW
#  define PTE_PAGE_BIT_RW        (1ULL << 1)       /* writeable */
#  define PTE_PAGE_BIT_NX        (1ULL << 63)      /* No execute: only valid after cpuid check */
# endif

# ifndef PG_1G_SZ
#  define PG_1G_SZ sizeof(uint8_t) * 1024 * 1024 * 1024
# endif
# ifndef PG_2M_SZ
#  define PG_2M_SZ sizeof(uint8_t) * 1024 * 1024 * 2
# endif
# ifndef PG_4K_SZ
#  define PG_4K_SZ sizeof(uint8_t) * 1024 * 4
# endif

# ifndef PAGE_1G_MASK
#  define PAGE_1G_MASK (long)~(PG_1G_SZ -1)
# endif
# ifndef PAGE_2M_MASK
#  define PAGE_2M_MASK (long)~(PG_2M_SZ -1)
# endif
# ifndef PAGE_4K_MASK
#  define PAGE_4K_MASK (long)~(PG_4K_SZ -1)
# endif
# ifndef DIV_ROUND_UP   /* offset, page_size */
#  define DIV_ROUND_UP (((n) + (d) - 1) / (d))
# endif

# define OFFSET_IN_1GPG(x) ((unsigned long)(x) & ~PAGE_1G_MASK)
# define OFFSET_IN_2MPG(x) ((unsigned long)(x) & ~PAGE_2M_MASK)
# define OFFSET_IN_4KPG(x) ((unsigned long)(x) & ~PAGE_4K_MASK)

__attribute__((used))
static void set_addr_rw(volatile uint64_t *pte){
	if( pte && (pte[0] &~ PTE_PAGE_BIT_RW) )
		pte[0] |= PTE_PAGE_BIT_RW;
}
__attribute__((used))
static void set_addr_ro(volatile uint64_t *pte){
	if( pte && (pte[0] & PTE_PAGE_BIT_RW) )
		pte[0] ^= PTE_PAGE_BIT_RW;
}
__attribute__((used))
static void set_addr_ex(volatile uint64_t *pte){
	if( pte && (pte[0] & PTE_PAGE_BIT_NX) )
		pte[0] ^= PTE_PAGE_BIT_NX;
	__asm__("cpuid  \n\t");
}
__attribute__((used))
static void set_addr_nx(volatile uint64_t *pte){
	if( pte && (pte[0] &~ PTE_PAGE_BIT_NX) )
		pte[0] ^= PTE_PAGE_BIT_NX;
	__asm__("cpuid  \n\t");
}

////////////////////////////////////////////////////////////////////////////////
// IN-kernel length disassembler engine (x86 only, 2.6.33+)
////////////////////////////////////////////////////////////////////////////////
/*|CALLBACK|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*//*|*/
/* то есть реализация write будет что-то типа:
** Since our target address can be at the page boundary - we should care about
** So, we calculate how max many pages it can lie on, and check each
***/

typedef struct pte_pair {
	uint64_t *ppte;
	uint64_t pte;
} pte_pair_t;

typedef struct pte_vector_struct {
	uint64_t count;	/* summary work with */
	uint64_t psize; /* type of page working with */
	pte_pair_t vt[ ]; /* [*ppte] [pte]  pair */
} pte_v_t;

#endif /* USE_PTE_FAM */

/* $rax - returned by callback value, or -E
 * @kaddr - where to apply patch
 * @len - how much space will be patched
 * @actor - callback, who will be doing patch-work.
 * @cbarg - callback's arguments
***/
#define PATCH_K(kaddr, len, actor, cbarg) \
	__patch_k((uint64_t)kaddr, (uint64_t)len, (uint64_t)actor, (struct pt_regs *)cbarg)
static uint64_t __patch_k(uint64_t kaddr, uint64_t len, uint64_t actor, struct pt_regs *cbarg) {
	uint64_t ret = 0x00;
#ifdef USE_PTE_FAM
	/* since this will be work under stop_machine we can't allocate */
	uint8_t mvector[0x1000];
	pte_v_t *mvt = ((typeof(mvt))mvector);
	int pg_touched = 0x00;

	/* at the moment we can store 255 pairs of pte */
	uint64_t *curr_ppte;
	uint32_t pflag;
	size_t psize;
	int i1, i2;

	if ( !virt_addr_valid( kaddr ) )
		return -EINVAL;

	memset(mvt, 0x00, 0x1000);

	/* determinating address's page info */
	curr_ppte = (uint64_t*)lookup_address( kaddr, &pflag );
	switch( pflag ){
		case PG_LEVEL_4K:
			psize = PG_4K_SZ;
			pg_touched = DIV_ROUND_UP(
				(OFFSET_IN_4KPG(kaddr) + len), PG_4K_SZ);
			break;
		case PG_LEVEL_2M:
			psize = PG_2M_SZ;
			pg_touched = DIV_ROUND_UP(
				(OFFSET_IN_2MPG(kaddr) + len), PG_2M_SZ);
			break;
		case PG_LEVEL_1G:
			psize = PG_1G_SZ;
			pg_touched = DIV_ROUND_UP(
				(OFFSET_IN_1GPG(kaddr) + len), PG_1G_SZ);
			break;
		default:
		return -1;
		break;
	}

	printk("page's size = %#lx, pages touched = %d\n", psize, pg_touched);
	if( pg_touched > 255 ){
		printk("Overflowed!\n");
		return -ENOMEM;
	}
	mvt->psize = psize;

	/* extracting original values and disable WP */
	for( i1 = 0; i1 < pg_touched; i1++ ){
		mvt->count++;
		mvt->vt[i1].ppte = ((void*)curr_ppte) + (i1 * sizeof(void*));
		mvt->vt[i1].pte = curr_ppte[i1];
		set_addr_rw( mvt->vt[i1].ppte );
	}
	printk("Original PTE's dumped, protection disabled, can continue.\n");
#endif
#ifdef USE_CR0_FAM
	if( !is_cr0_switched )
		kernel_write_enter();
#endif
ASM_CLI;
	ret = CALLADDR6(actor, cbarg->di, cbarg->si, cbarg->dx, cbarg->cx, cbarg->r8, cbarg->r9);
	printk("Callback done, returned value: %#llx\n", ret);
ASM_STI;
#ifdef USE_CR0_FAM
	if( is_cr0_switched )
		kernel_write_leave();
#endif
#ifdef USE_PTE_FAM
	for( i2 = mvt->count - 1; i2 >= 0x00; i2-- ){
		mvt->vt[i2].ppte[0] = mvt->vt[i2].pte;
	}
	printk("Original PTE's restored, protection enabled, job done.\n");
#endif
	return ret;
}


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
	struct pt_regs cbarg;

	memset(&cbarg, 0x00, sizeof(cbarg));

/* if we patch nop[rax+rax] instrumented function
 * will it conflict with ftrace() if try to set ftrace() after our hook?
***/
	if (hook->target.addr[0] == (char)0xE9 ||
	    hook->target.addr[0] == (char)0xCC) return;

	BUILD_BUG_ON(sizeof(khook_stub_template) > offsetof(khook_stub_t, nbytes));
	memcpy(stub, khook_stub_template, sizeof(khook_stub_template));
	stub_fixup(stub->hook, hook->fn);

	while (stub->nbytes < 5)
		stub->nbytes += khook_arch_lde_get_length(hook->target.addr + stub->nbytes);

	memcpy(stub->orig, hook->target.addr, stub->nbytes);
	x86_put_jmp(stub->orig + stub->nbytes, stub->orig + stub->nbytes,
		hook->target.addr + stub->nbytes);

	cbarg.di = (uint64_t)hook->target.addr, cbarg.si = (uint64_t)hook->target.addr;
	cbarg.dx = (hook->flags & KHOOK_F_NOREF) ? (uint64_t)hook->fn : (uint64_t)stub->hook;
	PATCH_K(cbarg.di, 0x05, &x86_put_jmp, &cbarg);

	hook->orig = stub->orig; // the only link from hook to stub
}

static inline void khook_arch_sm_cleanup_one(khook_t *hook) {
	khook_stub_t *stub = KHOOK_STUB(hook);
	struct pt_regs cbarg;

	memset(&cbarg, 0x00, sizeof(cbarg));
	cbarg.di = (uint64_t)hook->target.addr, cbarg.si = (uint64_t)stub->orig,
		cbarg.dx = stub->nbytes;
	PATCH_K(cbarg.di, cbarg.dx, &memcpy, &cbarg);
}

#define KHOOK_ARCH_INIT(...)					\
	(khook_arch_lde_init())
