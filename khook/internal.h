#pragma once

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/kallsyms.h>
#include <linux/stop_machine.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>

#ifdef CONFIG_KPROBES
# include <linux/kprobes.h>
#endif

#ifndef for_each_process
# include <linux/sched/signal.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
# define stop_machine stop_machine
#else
# define stop_machine stop_machine_run
#endif

#include "engine.h"

extern khook_t KHOOK_tbl[];
extern khook_t KHOOK_tbl_end[];

extern unsigned long KHOOK_STUB_hook[];
extern unsigned long KHOOK_STUB_hook_end[];
extern unsigned long KHOOK_STUB_hook_noref[];
extern unsigned long KHOOK_STUB_hook_noref_end[];

#define KHOOK_FOREACH_HOOK(p)		\
	for (p = KHOOK_tbl; p < KHOOK_tbl_end; p++)

extern long khook_arch_init(void);
extern void khook_arch_sm_init_one(khook_t *hook);
extern void khook_arch_sm_cleanup_one(khook_t *hook);
extern long khook_arch_write_kernel(long (*)(void *), void *);
