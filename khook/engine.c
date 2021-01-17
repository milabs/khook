#include "internal.h"

static khook_stub_t *khook_stub_tbl = NULL;

////////////////////////////////////////////////////////////////////////////////

static long lookupName = 0;
module_param(lookupName, long, 0);

// kernel module loader STB_WEAK binding hack
extern __attribute__((weak)) unsigned long kallsyms_lookup_name(const char *);

unsigned long khook_lookup_name(const char *name)
{
	static typeof(khook_lookup_name) *lookup_name = kallsyms_lookup_name;
#ifdef CONFIG_KPROBES
	if (NULL == lookup_name) {
		struct kprobe probe;
		int callback(struct kprobe *p, struct pt_regs *regs) {
			return 0;
		}
		memset(&probe, 0, sizeof(probe));
		probe.pre_handler = callback;
		probe.symbol_name = "kallsyms_lookup_name";
		if (!register_kprobe(&probe)) {
			lookup_name = (void *)probe.addr;
			unregister_kprobe(&probe);
		}
	}
#endif
	if (NULL == lookup_name)
		lookup_name = (void *)lookupName;
	return lookup_name ? lookup_name(name) : 0;
}

////////////////////////////////////////////////////////////////////////////////

#ifdef CONFIG_X86
# include "x86/hook.c"
#else
# error Target CPU architecture is NOT supported !!!
#endif

////////////////////////////////////////////////////////////////////////////////

static void khook_wakeup(void)
{
	struct task_struct *p;
	rcu_read_lock();
	for_each_process(p) {
		wake_up_process(p);
	}
	rcu_read_unlock();
}

static int khook_sm_init_hooks(void *arg)
{
	khook_t *p;
	KHOOK_FOREACH_HOOK(p) {
		if (!p->target.addr) continue;
		khook_arch_sm_init_one(p);
	}
	return 0;
}

static int khook_sm_cleanup_hooks(void *arg)
{
	khook_t *p;
	KHOOK_FOREACH_HOOK(p) {
		if (!p->target.addr) continue;
		khook_arch_sm_cleanup_one(p);
	}
	return 0;
}

static void khook_resolve(void)
{
	khook_t *p;
	KHOOK_FOREACH_HOOK(p) {
		p->target.addr = (void *)khook_lookup_name(p->target.name);
		if (!p->target.addr) printk("khook: failed to lookup %s symbol\n", p->target.name);
	}
}

static void khook_release(void)
{
	khook_t *p;
	KHOOK_FOREACH_HOOK(p) {
		khook_stub_t *stub = KHOOK_STUB(p);
		if (!p->target.addr) continue;
		while (atomic_read(&stub->use_count) > 0) {
			khook_wakeup();
			msleep_interruptible(1000);
			printk("khook: waiting for %s...\n", p->target.name);
		}
	}
	vfree(khook_stub_tbl);
}

////////////////////////////////////////////////////////////////////////////////

int khook_init(void)
{
	void *(*malloc)(long size) = NULL;
	int   (*set_memory_x)(unsigned long, int) = NULL;

	malloc = (void *)khook_lookup_name("module_alloc");
	if (!malloc || KHOOK_ARCH_INIT()) return -EINVAL;

	khook_stub_tbl = malloc(KHOOK_STUB_TBL_SIZE);
	if (!khook_stub_tbl) return -ENOMEM;
	memset(khook_stub_tbl, 0, KHOOK_STUB_TBL_SIZE);

	//
	// Since some point memory allocated by module_alloc() doesn't
	// have eXecutable attributes. That's why we have to mark the
	// region executable explicitly.
	//

	set_memory_x = (void *)khook_lookup_name("set_memory_x");
	if (set_memory_x) {
		int numpages = round_up(KHOOK_STUB_TBL_SIZE, PAGE_SIZE) / PAGE_SIZE;
		set_memory_x((unsigned long)khook_stub_tbl, numpages);
	}

	khook_resolve();
	stop_machine(khook_sm_init_hooks, NULL, 0);

	return 0;
}

void khook_cleanup(void)
{
	stop_machine(khook_sm_cleanup_hooks, NULL, 0);
	khook_release();
}
