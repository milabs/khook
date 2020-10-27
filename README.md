# 0

KHOOK (خوک) - Linux Kernel hooking engine.

# Usage

Include KHOOK engine:
~~~
#include "khook/engine.c"
~~~

Add the following line to the KBuild/Makefile:
~~~
ldflags-y += -T$(src)/khook/engine.lds (use LDFLAGS for old kernels)
~~~

Use `khook_init()` and `khook_cleanup()` to initalize and de-initialize hooking engine.

# Examples

## Hooking of generic kernel functions 

An example of hooking a kernel function with known prototype (function is defined in `linux/fs.h`):
~~~
#include <linux/fs.h> // has inode_permission() proto
KHOOK(inode_permission);
static int khook_inode_permission(struct inode *inode, int mask)
{
        int ret = 0;
        ret = KHOOK_ORIGIN(inode_permission, inode, mask);
        printk("%s(%p, %08x) = %d\n", __func__, inode, mask, ret);
        return ret;
}
~~~

An example of hooking a kernel function with custom prototype (function is not defined in `linux/binfmts.h`):
~~~
#include <linux/binfmts.h> // has no load_elf_binary() proto
KHOOK_EXT(int, load_elf_binary, struct linux_binprm *);
static int khook_load_elf_binary(struct linux_binprm *bprm)
{
        int ret = 0;
        ret = KHOOK_ORIGIN(load_elf_binary, bprm);
        printk("%s(%p) = %d (%s)\n", __func__, bprm, ret, bprm->filename);
        return ret;
}
~~~

Starting from [a6e7f394](https://github.com/milabs/khook/commit/a6e7f3945a4eebb811818f62bd2cf2ea50f609c0) it's possible to hook a function with big amount of arguments. This requires for `KHOOK` to make a local copy of N (hardcoded as 8) arguments which are passed through the stack before calling the handler function.

An example of hooking 12 argument function `scsi_execute` is shown below (see [#5](/../../issues/5) for details):

~~~

#include <scsi/scsi_device.h>
KHOOK(scsi_execute);
static int khook_scsi_execute(struct scsi_device *sdev, const unsigned char *cmd, int data_direction, void *buffer, unsigned bufflen, unsigned char *sense, struct scsi_sense_hdr *sshdr, int timeout, int retries, u64 flags, req_flags_t rq_flags, int *resid)
{
        int ret = 0;
        ret = KHOOK_ORIGIN(scsi_execute, sdev, cmd, data_direction, buffer, bufflen, sense, sshdr, timeout, retries, flags, rq_flags, resid);
        printk("%s(%lx, %lx, %lx, %lx, %lx, %lx, %lx, %lx, %lx, %lx, %lx, %lx) = %d\n", __func__, (long)sdev, (long)cmd, (long)data_direction, (long)buffer, (long)bufflen, (long)sense, (long)sshdr, (long)timeout, (long)retries, (long)flags, (long)rq_flags, (long)resid ,ret);
        return ret;
}

~~~

## Hooking of system calls (handler functions)

An example of hooking `kill(2)` system call handler (see [#3](/../../issues/3) for the details):
~~~
// long sys_kill(pid_t pid, int sig)
KHOOK_EXT(long, sys_kill, long, long);
static long khook_sys_kill(long pid, long sig) {
        printk("sys_kill -- %s pid %ld sig %ld\n", current->comm, pid, sig);
        return KHOOK_ORIGIN(sys_kill, pid, sig);
}

// long sys_kill(const struct pt_regs *regs) -- modern kernels
KHOOK_EXT(long, __x64_sys_kill, const struct pt_regs *);
static long khook___x64_sys_kill(const struct pt_regs *regs) {
        printk("sys_kill -- %s pid %ld sig %ld\n", current->comm, regs->di, regs->si);
        return KHOOK_ORIGIN(__x64_sys_kill, regs);
}
~~~

# Features

- x86 only
- 2.6.33+ kernels
- use of in-kernel length disassembler

# How it works?

The diagram below illustrates the call to function `X` without hooking:

~~~
CALLER
| ...
| CALL X -(1)---> X
| ...  <----.     | ...
` RET       |     ` RET -.
            `--------(2)-'
~~~

The diagram below illustrates the call to function `X` when `KHOOK` is used:

~~~
CALLER
| ...
| CALL X -(1)---> X
| ...  <----.     | JUMP -(2)----> STUB.hook
` RET       |     | ???            | INCR use_count
            |     | ...  <----.    | CALL handler -(3)------> HOOK.fn
            |     | ...       |    | DECR use_count <----.    | ...
            |     ` RET -.    |    ` RET -.              |    | CALL origin -(4)-----> STUB.orig
            |            |    |           |              |    | ...  <----.            | N bytes of X
            |            |    |           |              |    ` RET -.    |            ` JMP X + N -.
            `------------|----|-------(8)-'              '-------(7)-'    |                         |
                         |    `-------------------------------------------|---------------------(5)-'
                         `-(6)--------------------------------------------'
~~~

# License

This software is licensed under the GPL.

# Author

[Ilya V. Matveychikov](https://github.com/milabs)

2018, 2019, 2020
