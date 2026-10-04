/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * FileGuard character device - user/kernel shared ABI.
 * Included by the kernel module AND by the C++ application (DriverManager).
 * Only fixed-width types are used so both sides agree on the layout.
 */
#ifndef FILEGUARD_IOCTL_H
#define FILEGUARD_IOCTL_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define FG_DEVICE_NAME    "fileguard"
#define FG_DRIVER_VERSION 1u

enum fg_event_type {
	FG_EVT_NONE                   = 0, /* invalid, rejected by the driver */
	FG_EVT_UNAUTHORIZED_ACCESS    = 1,
	FG_EVT_INTEGRITY_FAILURE      = 2,
	FG_EVT_PROTECTED_FILE_OPEN    = 3,
	FG_EVT_PROTECTED_FILE_CREATED = 4,
	FG_EVT_MAX                    = 5  /* number of slots, not a valid type */
};

/* 32 bytes. type/file_num/user_id come from user space; the kernel
 * overwrites pid, uid, timestamp so they cannot be spoofed. */
struct fg_event {
	__u32 type;
	__u32 file_num;   /* numeric part of FG-<n> */
	__u32 user_id;    /* FileGuard application user id (informational) */
	__u32 pid;        /* kernel-filled: tgid of the writer */
	__u32 uid;        /* kernel-filled: Linux uid of the writer */
	__u32 reserved;   /* must be zero from user space; kernel zeroes it */
	__u64 timestamp;  /* kernel-filled: seconds since epoch */
};

/* 64 bytes */
struct fg_stats {
	__u64 total;                   /* events accepted since load/clear */
	__u64 dropped;                 /* events rejected because queue was full */
	__u64 per_type[FG_EVT_MAX];    /* index = enum fg_event_type */
	__u32 pending;                 /* events currently queued */
	__u32 capacity;                /* queue capacity */
};

#define FG_IOC_MAGIC       'F'
#define FG_IOC_GET_STATS   _IOR(FG_IOC_MAGIC, 1, struct fg_stats)
#define FG_IOC_CLEAR       _IO(FG_IOC_MAGIC, 2)             /* CAP_SYS_ADMIN */
#define FG_IOC_GET_VERSION _IOR(FG_IOC_MAGIC, 3, __u32)

#endif /* FILEGUARD_IOCTL_H */
