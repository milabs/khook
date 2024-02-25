#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>

#include <khook/engine.h>

////////////////////////////////////////////////////////////////////////////////
// An example of using KHOOK
////////////////////////////////////////////////////////////////////////////////

#include <linux/fs.h>

KHOOK(inode_permission);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)

static int khook_inode_permission(struct mnt_idmap *idmap, struct inode *inode, int mask)
{
	int ret = 0;

	ret = KHOOK_ORIGIN(inode_permission, idmap, inode, mask);
	printk("%s(%p, %08x) = %d\n", __func__, inode, mask, ret);

	return ret;
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)

static int khook_inode_permission(struct user_namespace *mnt_userns, struct inode *inode, int mask)
{
	int ret = 0;

	ret = KHOOK_ORIGIN(inode_permission, mnt_userns, inode, mask);
	printk("%s(%p, %08x) = %d\n", __func__, inode, mask, ret);

	return ret;
}

#else

static int khook_inode_permission(struct inode *inode, int mask)
{
	int ret = 0;

	ret = KHOOK_ORIGIN(inode_permission, inode, mask);
	printk("%s(%p, %08x) = %d\n", __func__, inode, mask, ret);

	return ret;
}

#endif

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
