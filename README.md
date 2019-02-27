# 0

KHOOK (خوک) - Linux Kernel hooking engine.

# Usage

Include KHOOK engine:
~~~
#include "khook/engine.c"
~~~

Add the following line to the KBuild/Makefile:
~~~
ldflags-y += -T$(src)/khook/engine.lds
~~~

Use `khook_init()` and `khook_cleanup()` to initalize and de-initialize hooking engine.

# Examples

An example of hooking of kernel function with known prototype (function is defined in `linux/fs.h`):
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

An example of hooking of kernel function with custom prototype (function is not defined in `linux/binfmts.h`):
~~~
#include <linux/binfmts.h> // has no load_elf_binary() proto
KHOOK_EXT(int, load_elf_binary, struct linux_binprm *);
static int khook_load_elf_binary(struct linux_binprm *bprm)
{
        int ret = 0;
        ret = KHOOK_ORIGIN(load_elf_binary, bprm);
        printk("%s(%p) = %d\n", __func__, bprm, ret);
        return ret;
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
            |     ` RET -.    |    ` RET -.              |    | CALL origin -(4)------> STUB.orig
            |            |    |           |              |    | ...  <----.             | N bytes of X
            |            |    |           |              |    ` RET -.    |             ` JMP X + N -.
            `------------|----|-------(8)-'              '-------(7)-'    |                          |
                         |    `-------------------------------------------|----------------------(5)-'
                         `-(6)--------------------------------------------'
~~~

# License

This software is licensed under the GPL.

# Author

[Ilya V. Matveychikov](https://github.com/milabs)

2018, 2019
