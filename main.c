#include <linux/kernel.h>
#include <linux/module.h>

#include "khook/engine.c"

#include <linux/fs.h>
#include <linux/sched.h>

/*******************************************************************************
* Hooking _do_fork
*
* It looks that several syscalls related to process creation eventually call
* __do_fork. Therefore it is better to hook it rather than individual syscalls.
*
*******************************************************************************/

KHOOK_EXT(long, _do_fork, unsigned long clone_flags,
							unsigned long stack_start,
							unsigned long stack_size,
							int __user *parent_tidptr,
							int __user *child_tidptr,
							unsigned long tls);
static long khook__do_fork(unsigned long clone_flags,
							unsigned long stack_start, unsigned long stack_size,
							int __user *parent_tidptr, int __user *child_tidptr,
							unsigned long tls) {
	long ret = 0;

	ret = KHOOK_ORIGIN(_do_fork, clone_flags, stack_start, stack_size,
		parent_tidptr, child_tidptr, tls);

	printk("%s: executable %s, pid %ld\n", __func__, current->comm, ret);
	return ret;
}

/*******************************************************************************
* Hooking sys_kill and __x64_sys_kill
*
* Newer kernels changed their prefix for syscalls there for __x64_sys_kill
* should be tracked.
*
*******************************************************************************/

// long sys_kill(pid_t pid, int sig)
KHOOK_EXT(long, sys_kill, long, long);
static long khook_sys_kill(long pid, long sig) {
	printk("%s: executable %s, pid %ld, sig %ld\n", __func__, current->comm,
		pid, sig);
	return KHOOK_ORIGIN(sys_kill, pid, sig);
}

// This is the hook when process is killed. For example by "kill -9 <pid>"
// long sys_kill(const struct pt_regs *regs) -- modern kernels
KHOOK_EXT(long, __x64_sys_kill, const struct pt_regs *);
static long khook___x64_sys_kill(const struct pt_regs *regs) {
	printk("%s: executable %s, pid %ld, sig %ld\n", __func__, current->comm,
		regs->di, regs->si);
	return KHOOK_ORIGIN(__x64_sys_kill, regs);
}

/*******************************************************************************
* Hooking load_elf_binary
*
* We are going to get executable name and additional information here after elf
* is loaded. Some of this useful info can be VM_AREAs of the task.
*******************************************************************************/

#include <linux/binfmts.h>

KHOOK_EXT(int, load_elf_binary, struct linux_binprm *);
static int khook_load_elf_binary(struct linux_binprm *bprm)
{
	int ret = 0;

	ret = KHOOK_ORIGIN(load_elf_binary, bprm);
	printk("%s: filename %s, real file name %s, return %d\n", __func__,
		bprm->filename, bprm->interp, ret);

	/* Worth also looking into bprm->vma_pages and  bprm->vma */

	return ret;
}

int init_module(void)
{
	return khook_init();
}

void cleanup_module(void)
{
	khook_cleanup();
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hooking processes creation and termination");
MODULE_AUTHOR("Yan Vugenfirer <yan@bladerunner.io> based on work by Ilya V. Matveychikov");
