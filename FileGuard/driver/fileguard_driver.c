// SPDX-License-Identifier: GPL-2.0
/*
 * FileGuard security-event character device (/dev/fileguard).
 *
 * Purpose : bounded kernel-side channel for security events sent by the
 *           FileGuard user-space application.
 * Not     : an encryption engine, an access-control enforcer, or tamper-proof
 *           storage. It is a small, educational event buffer.
 *
 * Target  : Ubuntu 24.04 LTS, kernel 6.8 series (guards below keep it
 *           building on 5.15..6.11 for the APIs that changed).
 *
 * Interface
 *   write(fd, struct fg_event, 32)  enqueue an event (strict size, validated)
 *   read (fd, buf, >=32)            dequeue oldest event, -EAGAIN when empty
 *   ioctl FG_IOC_GET_STATS          counters
 *   ioctl FG_IOC_GET_VERSION        driver ABI version
 *   ioctl FG_IOC_CLEAR              reset queue+counters (CAP_SYS_ADMIN)
 *   /proc/fileguard                 human-readable counters (read-only)
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/timekeeping.h>
#include <linux/version.h>
#include <linux/atomic.h>
#include <linux/build_bug.h>

#include "fileguard_ioctl.h"

#define FG_QUEUE_CAPACITY 256u

struct fg_state {
	dev_t               devt;
	struct cdev         cdev;
	struct class       *cls;
	struct device      *dev;
	struct proc_dir_entry *proc;
	struct mutex        lock;          /* protects ring + stats */
	struct fg_event    *ring;          /* kcalloc'd, FG_QUEUE_CAPACITY slots */
	unsigned int        head;          /* next slot to read */
	unsigned int        count;         /* queued events */
	struct fg_stats     stats;
	atomic_t            open_count;
};

static struct fg_state fg;

static const char * const fg_type_names[FG_EVT_MAX] = {
	"NONE", "UNAUTHORIZED_ACCESS", "INTEGRITY_FAILURE",
	"PROTECTED_FILE_OPEN", "PROTECTED_FILE_CREATED",
};

/* ---- ring buffer (caller holds fg.lock) -------------------------------- */

static int fg_push_locked(const struct fg_event *ev)
{
	unsigned int tail;

	if (fg.count >= FG_QUEUE_CAPACITY) {
		fg.stats.dropped++;
		return -ENOBUFS;
	}
	tail = (fg.head + fg.count) % FG_QUEUE_CAPACITY;
	fg.ring[tail] = *ev;
	fg.count++;
	fg.stats.total++;
	fg.stats.per_type[ev->type]++;   /* type validated by caller */
	return 0;
}

/* ---- file operations --------------------------------------------------- */

static int fg_open(struct inode *inode, struct file *file)
{
	nonseekable_open(inode, file);
	atomic_inc(&fg.open_count);
	return 0;
}

static int fg_release(struct inode *inode, struct file *file)
{
	atomic_dec(&fg.open_count);
	return 0;
}

static ssize_t fg_write(struct file *file, const char __user *buf,
			size_t len, loff_t *off)
{
	struct fg_event ev;
	int ret;

	if (len != sizeof(ev))              /* strict: exactly one event */
		return -EINVAL;
	if (copy_from_user(&ev, buf, sizeof(ev)))
		return -EFAULT;
	if (ev.type == FG_EVT_NONE || ev.type >= FG_EVT_MAX)
		return -EINVAL;

	/* never trust identity/time supplied by user space */
	ev.pid       = task_tgid_vnr(current);
	ev.uid       = from_kuid(&init_user_ns, current_uid());
	ev.reserved  = 0;
	ev.timestamp = (__u64)ktime_get_real_seconds();

	ret = mutex_lock_interruptible(&fg.lock);
	if (ret)
		return ret;
	ret = fg_push_locked(&ev);
	mutex_unlock(&fg.lock);
	if (ret)
		return ret;

	pr_info_ratelimited("fileguard: event %s file=FG-%u user=%u pid=%u uid=%u\n",
			    fg_type_names[ev.type], ev.file_num, ev.user_id,
			    ev.pid, ev.uid);
	return sizeof(ev);
}

static ssize_t fg_read(struct file *file, char __user *buf,
		       size_t len, loff_t *off)
{
	int ret;

	if (len < sizeof(struct fg_event))
		return -EINVAL;

	ret = mutex_lock_interruptible(&fg.lock);
	if (ret)
		return ret;
	if (fg.count == 0) {
		mutex_unlock(&fg.lock);
		return -EAGAIN;
	}
	/* copy first, advance only on success so a bad pointer loses nothing */
	if (copy_to_user(buf, &fg.ring[fg.head], sizeof(struct fg_event))) {
		mutex_unlock(&fg.lock);
		return -EFAULT;
	}
	fg.head = (fg.head + 1) % FG_QUEUE_CAPACITY;
	fg.count--;
	mutex_unlock(&fg.lock);
	return sizeof(struct fg_event);
}

static long fg_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	int ret;

	if (_IOC_TYPE(cmd) != FG_IOC_MAGIC)
		return -ENOTTY;

	switch (cmd) {
	case FG_IOC_GET_STATS: {
		struct fg_stats s;

		ret = mutex_lock_interruptible(&fg.lock);
		if (ret)
			return ret;
		s = fg.stats;
		s.pending  = fg.count;
		s.capacity = FG_QUEUE_CAPACITY;
		mutex_unlock(&fg.lock);
		return copy_to_user(uarg, &s, sizeof(s)) ? -EFAULT : 0;
	}
	case FG_IOC_GET_VERSION:
		return put_user((__u32)FG_DRIVER_VERSION, (__u32 __user *)uarg);
	case FG_IOC_CLEAR:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		ret = mutex_lock_interruptible(&fg.lock);
		if (ret)
			return ret;
		fg.head = 0;
		fg.count = 0;
		memset(&fg.stats, 0, sizeof(fg.stats));
		mutex_unlock(&fg.lock);
		return 0;
	default:
		return -ENOTTY;
	}
}

static const struct file_operations fg_fops = {
	.owner          = THIS_MODULE,
	.open           = fg_open,
	.release        = fg_release,
	.read           = fg_read,
	.write          = fg_write,
	.unlocked_ioctl = fg_ioctl,
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
	.llseek         = no_llseek,
#endif
};

/* ---- /proc/fileguard --------------------------------------------------- */

static int fg_proc_show(struct seq_file *m, void *v)
{
	unsigned int i;

	mutex_lock(&fg.lock);
	seq_printf(m, "version:  %u\n", FG_DRIVER_VERSION);
	seq_printf(m, "opens:    %d\n", atomic_read(&fg.open_count));
	seq_printf(m, "pending:  %u/%u\n", fg.count, FG_QUEUE_CAPACITY);
	seq_printf(m, "total:    %llu\n", fg.stats.total);
	seq_printf(m, "dropped:  %llu\n", fg.stats.dropped);
	for (i = 1; i < FG_EVT_MAX; i++)
		seq_printf(m, "%-24s %llu\n", fg_type_names[i], fg.stats.per_type[i]);
	mutex_unlock(&fg.lock);
	return 0;
}

/* ---- device node permissions (0660; group set by udev rule/script) ----- */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
static char *fg_devnode(const struct device *dev, umode_t *mode)
#else
static char *fg_devnode(struct device *dev, umode_t *mode)
#endif
{
	if (mode)
		*mode = 0660;
	return NULL;
}

/* ---- module init/exit -------------------------------------------------- */

static int __init fg_init(void)
{
	int ret;

	BUILD_BUG_ON(sizeof(struct fg_event) != 32);
	BUILD_BUG_ON(sizeof(struct fg_stats) != 64);

	mutex_init(&fg.lock);
	atomic_set(&fg.open_count, 0);

	fg.ring = kcalloc(FG_QUEUE_CAPACITY, sizeof(*fg.ring), GFP_KERNEL);
	if (!fg.ring)
		return -ENOMEM;

	ret = alloc_chrdev_region(&fg.devt, 0, 1, FG_DEVICE_NAME);
	if (ret)
		goto err_ring;

	cdev_init(&fg.cdev, &fg_fops);
	fg.cdev.owner = THIS_MODULE;
	ret = cdev_add(&fg.cdev, fg.devt, 1);
	if (ret)
		goto err_region;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	fg.cls = class_create(FG_DEVICE_NAME);
#else
	fg.cls = class_create(THIS_MODULE, FG_DEVICE_NAME);
#endif
	if (IS_ERR(fg.cls)) {
		ret = PTR_ERR(fg.cls);
		goto err_cdev;
	}
	fg.cls->devnode = fg_devnode;

	fg.dev = device_create(fg.cls, NULL, fg.devt, NULL, FG_DEVICE_NAME);
	if (IS_ERR(fg.dev)) {
		ret = PTR_ERR(fg.dev);
		goto err_class;
	}

	fg.proc = proc_create_single(FG_DEVICE_NAME, 0444, NULL, fg_proc_show);
	if (!fg.proc) {
		ret = -ENOMEM;
		goto err_device;
	}

	pr_info("fileguard: loaded (major %u, queue %u events) -> /dev/%s\n",
		MAJOR(fg.devt), FG_QUEUE_CAPACITY, FG_DEVICE_NAME);
	return 0;

err_device:
	device_destroy(fg.cls, fg.devt);
err_class:
	class_destroy(fg.cls);
err_cdev:
	cdev_del(&fg.cdev);
err_region:
	unregister_chrdev_region(fg.devt, 1);
err_ring:
	kfree(fg.ring);
	fg.ring = NULL;
	return ret;
}

static void __exit fg_exit(void)
{
	proc_remove(fg.proc);
	device_destroy(fg.cls, fg.devt);
	class_destroy(fg.cls);
	cdev_del(&fg.cdev);
	unregister_chrdev_region(fg.devt, 1);
	kfree(fg.ring);
	fg.ring = NULL;
	pr_info("fileguard: unloaded\n");
}

module_init(fg_init);
module_exit(fg_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("FileGuard capstone team");
MODULE_DESCRIPTION("FileGuard security event character device");
MODULE_VERSION("1.0");
