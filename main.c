#include <linux/kernel.h>
#include <linux/module.h>

#include "engine/engine.h"
#include "engine/engine.c"

////////////////////////////////////////////////////////////////////////////////
// An example of using KHOOK
////////////////////////////////////////////////////////////////////////////////

#include <linux/fs.h>

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

////////////////////////////////////////////////////////////////////////////////
// An example of using KHOOK_EXT
////////////////////////////////////////////////////////////////////////////////

#include <linux/binfmts.h>

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

////////////////////////////////////////////////////////////////////////////////

int init_module(void)
{
	return khook_init();
}

void cleanup_module(void)
{
	khook_cleanup();
}

MODULE_LICENSE("GPL");
