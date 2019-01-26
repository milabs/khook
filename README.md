# 0

KHOOK - Linux Kernel hooking engine.

# Usage

Include KHOOK engine:
~~~
#include "khook/engine.c"
~~~

Use `khook_init()` and `khook_cleanup()` to initalize and de-initialize hooking engine properly.

# Examples

An example of hooking of kernel function with known prototype (function is defined in `linux/fs.h`):
~~~
#include <linux/fs.h> // has inode_permission() proto
KHOOK(inode_permission);
static int khook_inode_permission(struct inode *inode, int mask)
{
	int ret = 0;

	KHOOK_GET(inode_permission);
	ret = KHOOK_ORIGIN(inode_permission, inode, mask);
	printk("%s(%p, %08x) = %d\n", __func__, inode, mask, ret);
	KHOOK_PUT(inode_permission);

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

	KHOOK_GET(load_elf_binary);
	ret = KHOOK_ORIGIN(load_elf_binary, bprm);
	printk("%s(%p) = %d\n", __func__, bprm, ret);
	KHOOK_PUT(load_elf_binary);

	return ret;
}
~~~

# Features

- x86 only
- 2.6.33+ kernels
- use of in-kernel length disassembler

# Author

[Ilya V. Matveychikov](https://github.com/milabs)

2018
