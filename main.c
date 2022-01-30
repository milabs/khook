#include <linux/kernel.h>
#include <linux/module.h>

#include "khook/engine.c"

#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/utsname.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <linux/uuid.h>

static struct kernel_info {
	unsigned int	a, b, c;
	char		release[__NEW_UTS_LEN + 1];
	char		version[__NEW_UTS_LEN + 1];
	uuid_t		uuid;
} kinfo = {};

////////////////////////////////////////////////////////////////////////////////

static struct {
	const char *	name;
	struct path	path;
	umode_t		mode;
} restrict_inodes[] = {
	{ "/boot" },
	{ "/lib/modules" },
	{ "/proc/modules" },
	{ "/proc/kallsyms" },
	{ "/proc/config.gz" },
};

static int show_cmdline(struct seq_file *m, void *v);
static int show_version(struct seq_file *m, void *v);

static struct {
	const char *name;
	int (*show)(struct seq_file *m, void *v);
	int (*show_orig)(struct seq_file *m, void *v);
} seq_forge_files[] = {
	{ "/proc/cmdline", show_cmdline },
	{ "/proc/version", show_version },
};

////////////////////////////////////////////////////////////////////////////////

static int seq_forge_init(void) {
	int i;

	for (i = 0; i < ARRAY_SIZE(seq_forge_files); i++) {
		struct file *f = NULL;
		if (!seq_forge_files[i].name)
			continue;
		if ((f = filp_open(seq_forge_files[i].name, 0, 0)) != NULL) {
			seq_forge_files[i].show_orig = ((struct seq_file *)f->private_data)->op->show;
			filp_close(f, NULL);
		} else {
			seq_forge_files[i].name = NULL;
		}
	}

	return 0;
}

KHOOK(single_open);
static int khook_single_open(struct file *file, int (*show)(struct seq_file *, void *), void *data) {
	int i, ret = KHOOK_ORIGIN(single_open, file, show, data);

	for (i = 0; !ret && i < ARRAY_SIZE(seq_forge_files); i++) {
		if (show == seq_forge_files[i].show_orig) {
			struct seq_file *seq = (void *)file->private_data;
			seq->private = seq_forge_files[i].show_orig; // pass origin to show()
			((struct seq_operations *)seq->op)->show = seq_forge_files[i].show;
			break;
		}
	}

	return ret;
}

static int show_version(struct seq_file *m, void *v) {
	int (*show_orig)(struct seq_file *, void *v) = (void *)m->private;
	if (!uid_eq(current_cred()->uid, GLOBAL_ROOT_UID)) {
		return seq_printf(m, "%s", kinfo.version), 0;
	} else {
		return show_orig(m, NULL);
	}
}

static int show_cmdline(struct seq_file *m, void *v) {
	int (*show_orig)(struct seq_file *, void *v) = (void *)m->private;
	if (!uid_eq(current_cred()->uid, GLOBAL_ROOT_UID)) {
		return seq_printf(m, "linux /boot/vmlinuz-%s root=UUID=%pUl quiet ro\n", kinfo.release, &kinfo.uuid), 0;
	} else {
		return show_orig(m, NULL);
	}
}

////////////////////////////////////////////////////////////////////////////////

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
		if (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode)) {
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
		memcpy(&orig, uts, sizeof(orig));
		snprintf(uts->version, sizeof(uts->version), "%s", kinfo.version);
		snprintf(uts->release, sizeof(uts->release), "%s", kinfo.release);
	} else {
		memcpy(utsname(), &orig, sizeof(orig));
		memset(&orig, 0, sizeof(orig));
	}
}

int init_module(void) {
	int ret = -EINVAL;

	seq_forge_init();

	kinfo.a = (LINUX_VERSION_CODE >> 16) & 0xff;
	kinfo.b = (LINUX_VERSION_CODE >>  8) & 0xff;
	kinfo.c = get_random_int() & 0xff;

	snprintf(kinfo.version,
		sizeof(kinfo.release),
		"# %s", KBUILD_BUILD_TIMESTAMP);
	snprintf(kinfo.release,
		sizeof(kinfo.release),
		"%u.%u.%u", kinfo.a, kinfo.b, kinfo.c);

	generate_random_uuid(kinfo.uuid.b);

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
