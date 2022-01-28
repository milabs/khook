#include <linux/kernel.h>
#include <linux/module.h>

#include "khook/engine.c"

#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/utsname.h>
#include <linux/random.h>

////////////////////////////////////////////////////////////////////////////////

static struct {
	dev_t		id;
} restrict_devs[] = {
	{ MKDEV(1, 11) }, // /dev/kmsg
};

static struct {
	const char *	name;
	struct path	path;
	umode_t		mode;
} restrict_inodes[] = {
	{ "/boot" },
	{ "/lib/modules" },
	// TODO: http://linuxmafia.com/faq/Admin/release-files.html
	{ "/proc/kmsg" },
	{ "/proc/version" },
	{ "/proc/cmdline" },
	{ "/proc/modules" },
	{ "/proc/kallsyms" },
	{ "/proc/config.gz" },
};

////////////////////////////////////////////////////////////////////////////////

static int do_restrict_dev(struct inode *inode) {
	int i;

	for (i = 0; i < ARRAY_SIZE(restrict_devs); i++) {
		if (inode->i_rdev == restrict_devs[i].id) {
			return -EPERM;
		}
	}

	return 0;
}

static int do_restrict_inodes(struct inode *inode) {
	int i;

	for (i = 0; i < ARRAY_SIZE(restrict_inodes); i++) {
		if (!restrict_inodes[i].name)
			continue;
		if (restrict_inodes[i].path.dentry->d_inode == inode) {
			return -EPERM;
		}
	}

	return 0;
}

static int init_restrict(void) {
	int i;

	for (i = 0; i < ARRAY_SIZE(restrict_inodes); i++) {
		if (!restrict_inodes[i].name)
			continue;
		if (kern_path(restrict_inodes[i].name, LOOKUP_FOLLOW, &restrict_inodes[i].path)) {
			printk("Unable to restrict %s\n", restrict_inodes[i].name);
			restrict_inodes[i].name = NULL;
		} else {
			restrict_inodes[i].mode = restrict_inodes[i].path.dentry->d_inode->i_mode;
			restrict_inodes[i].path.dentry->d_inode->i_mode &= 0777700;
			printk("Restricting user access to %s\n", restrict_inodes[i].name);
		}
	}

	return 0;
}

static void cleanup_restrict(void) {
	int i;

	for (i = 0; i < ARRAY_SIZE(restrict_inodes); i++) {
		if (!restrict_inodes[i].name)
			continue;
		restrict_inodes[i].path.dentry->d_inode->i_mode = restrict_inodes[i].mode;
		path_put(&restrict_inodes[i].path);
	}
}

////////////////////////////////////////////////////////////////////////////////

KHOOK(inode_permission);
static int khook_inode_permission(struct inode *inode, int mask) {
	int ret = KHOOK_ORIGIN(inode_permission, inode, mask);

	if (!ret && !uid_eq(current_cred()->uid, GLOBAL_ROOT_UID)) {
		if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
			ret = do_restrict_dev(inode);
		} else if (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode)) {
			ret = do_restrict_inodes(inode);
		}
	}

	return ret;
}

/* Prevent chmod() for restricted inodes */
KHOOK_EXT(int, chmod_common, const struct path *, umode_t);
static int khook_chmod_common(const struct path *path, umode_t mode) {
	if (do_restrict_inodes(path->dentry->d_inode)) {
		return -EPERM;
	} else {
		return KHOOK_ORIGIN(chmod_common, path, mode);
	}
}

/* Restrict dmesg for non-root users */
KHOOK_EXT(int, security_syslog, int, int);
static int khook_security_syslog(int type, int dummy) {
	if (!uid_eq(current_cred()->uid, GLOBAL_ROOT_UID)) {
		return -EPERM;
	} else {
		return KHOOK_ORIGIN(security_syslog, type, dummy);
	}
}

////////////////////////////////////////////////////////////////////////////////

static void forge_unforge_utsname(void) {
	static struct new_utsname orig = { 0 };
	typeof(orig) *uts = utsname();
	
	if (!orig.version[0]) {
		int rand = get_random_int();
		memcpy(&orig, uts, sizeof(orig));
		snprintf(uts->version, sizeof(uts->version), "# %s",
			 KBUILD_BUILD_TIMESTAMP);
		snprintf(uts->release,  sizeof(uts->release), "%u.%u.%u",
			 (LINUX_VERSION_CODE >> 16) & 0xff,
			 (LINUX_VERSION_CODE >> 8) & 0xff,
			 (LINUX_VERSION_CODE ^ rand) & 0xff);
	} else {
		memcpy(utsname(), &orig, sizeof(orig));
		memset(&orig, 0, sizeof(orig));
	}
}

int init_module(void) {
	int ret = -EINVAL;

	ret = init_restrict();
	if (ret) goto out;

	ret = khook_init();
	if (ret) goto out_cleanup;

	forge_unforge_utsname();

	return 0;

out_cleanup:
	cleanup_restrict();
out:
	return ret;
}

void cleanup_module(void) {
	khook_cleanup();
	cleanup_restrict();
	forge_unforge_utsname();
}

MODULE_LICENSE("GPL\0but who really cares?");
