#include <linux/kernel.h>
#include <linux/module.h>

#include "khook/engine.c"

////////////////////////////////////////////////////////////////////////////////
// An example of using KHOOK
////////////////////////////////////////////////////////////////////////////////

#include <linux/fs.h>

KHOOK(inode_permission);
static int khook_inode_permission(struct inode *inode, int mask)
{
	int ret = 0;

	ret = KHOOK_ORIGIN(inode_permission, inode, mask);
	printk("%s(%p, %08x) = %d\n", __func__, inode, mask, ret);

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

	ret = KHOOK_ORIGIN(load_elf_binary, bprm);
	printk("%s(%p) = %d (%s)\n", __func__, bprm, ret, bprm->filename);

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

MODULE_LICENSE("GPL\0but who really cares?");
