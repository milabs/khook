#include "internal.h"

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

long khook_write_kernel(long (*fn)(void *), void *arg) {
	return khook_arch_write_kernel(fn, arg);
}

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

static void khook_resolve(khook_lookup_t lookup)
{
	khook_t *p;
	KHOOK_FOREACH_HOOK(p) {
		p->target.addr = lookup ? \
			(void *)lookup(p->target.name) : \
			(void *)khook_lookup_name(p->target.name);
		if (!p->target.addr) pr_warn("khook: failed to lookup %s symbol\n", p->target.name);
	}
}

static void khook_release(void)
{
	khook_t *p;
	KHOOK_FOREACH_HOOK(p) {
		if (!p->target.addr) continue;
		while (atomic_read(&p->use_count) > 0) {
			khook_wakeup();
			msleep_interruptible(1000);
			pr_info("khook: waiting for %s...\n", p->target.name);
		}
	}
}

////////////////////////////////////////////////////////////////////////////////

int khook_init(khook_lookup_t lookup)
{
	const size_t max_stub_size = 0x80; // NOTE: keep in sync with value in engine.h

	if ((((void *)KHOOK_STUB_hook_end - (void *)KHOOK_STUB_hook) > max_stub_size) ||
	    (((void *)KHOOK_STUB_hook_noref_end - (void *)KHOOK_STUB_hook_noref_end) > max_stub_size)) {
		pr_err("khook: stub function size have to be increased\n");
		return -EINVAL;
	} else if (khook_arch_init()) {
		return -EINVAL;
	}

	khook_resolve(lookup);
	stop_machine(khook_sm_init_hooks, NULL, 0);

	return 0;
}

void khook_cleanup(void)
{
	stop_machine(khook_sm_cleanup_hooks, NULL, 0);
	khook_release();
}
