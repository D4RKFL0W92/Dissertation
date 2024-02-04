/*
 * Copyright (c) [2023], Calum Dawson
 * All rights reserved.
 * This code is the exclusive property of Calum Dawson.
 * Any unauthorized use or reproduction without the explicit
 * permission of Calum Dawson is strictly prohibited.
 * Unauthorized copying of this file, via any medium, is
 * strictly prohibited.
 * Proprietary and confidential.
 * Written by Calum Dawson calumjamesdawson@gmail.com, [2023].
*/

#ifndef _ELF_DYNAMIC_INFO_
#define _ELF_DYNAMIC_INFO_

#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <poll.h>
#include <sched.h>
#include <fcntl.h>
#include <utime.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <mqueue.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <sys/sem.h>
#include <sys/reg.h>
#include <sys/time.h>
#include <sys/swap.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/timex.h>
#include <sys/epoll.h>
#include <sys/timex.h>
#include <sys/xattr.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ptrace.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <linux/bpf.h>
#include <linux/rseq.h>
#include <linux/kcmp.h>
#include <linux/futex.h>
#include <linux/types.h>
#include <linux/kexec.h>
#include <linux/mount.h>
#include <linux/ioprio.h>
#include <linux/ptrace.h>
#include <linux/keyctl.h>
#include <linux/filter.h>
#include <linux/openat2.h>
#include <linux/aio_abi.h>
#include <linux/landlock.h>
#include <linux/membarrier.h>
#include <linux/perf_event.h>
#include "../Headers/elftypes.h"
#include "../ELFinfo/elfinfo.h"
#include "../../Logging/logging.h"
#include "../../Types/turtle_types.h"


#define PROGRESS_TO_SYSCALL_EXIT(pid) ptrace(PTRACE_SYSCALL, pid, NULL, NULL)

/* SYS_reboot options. */
#define LINUX_REBOOT_CMD_CAD_OFF    0x00
#define LINUX_REBOOT_CMD_CAD_ON     0x89abcdef
#define LINUX_REBOOT_CMD_HALT       0xcdef0123
#define LINUX_REBOOT_CMD_KEXEC      0x45584543
#define LINUX_REBOOT_CMD_POWER_OFF  0x4321fedc
#define LINUX_REBOOT_CMD_RESTART    0x1234567
#define LINUX_REBOOT_CMD_RESTART2   0xa1b2c3d4
#define LINUX_REBOOT_CMD_SW_SUSPEND 0xd000fce1

int8_t readStringFromProcessMemory(pid_t pid, uint64_t offset, char** pStr);
int8_t readProcessMemoryFromPID(pid_t pid, const void * offset, void * dstAddr, uint64_t uCount);


int8_t mapELF32ToHandleFromProcessMemory(const void ** pMem, ELF32_EXECUTABLE_HANDLE_T ** elfHandle, const uint64_t uCount);
int8_t mapELF64ToHandleFromProcessMemory(const void ** pMem, ELF64_EXECUTABLE_HANDLE_T ** elfHandle, const uint64_t uCount);


#ifdef UNITTEST
void elfDynamicTestSuite();
#endif /* UNITTEST */

////////////////////////////////////////////////////////////////

#ifndef linux_dirent
  struct linux_dirent
  {
    unsigned long  d_ino;     /* Inode number */
    unsigned long  d_off;     /* Offset to next linux_dirent */
    unsigned short d_reclen;  /* Length of this linux_dirent */
    char           d_name[];  /* Filename (null-terminated) */
                      /* length is actually (d_reclen - 2 -
                        offsetof(struct linux_dirent, d_name)) */
    /*
    char           pad;       // Zero padding byte
    char           d_type;    // File type (only since Linux
                              // 2.6.4); offset is (d_reclen - 1)
    */
  };
#endif /* linux_dirent */

////////////////////////////////////////////////////////////////

#ifndef mmsghdr
  struct mmsghdr
  {
    struct msghdr msg_hdr;  /* Message header */
    unsigned int  msg_len;  /* Number of received bytes for header */
  };
#endif /* mmsghdr */

////////////////////////////////////////////////////////////////

#ifndef file_handle
  struct file_handle
  {
    unsigned int  handle_bytes;   /* Size of f_handle [in, out] */
    int           handle_type;    /* Handle type [out] */
    unsigned char f_handle[0];    /* File identifier (sized by caller) [out] */
  };
#endif /* file_handle */

////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////

#ifndef sched_attr
  struct sched_attr
  {
    uint32_t size;              /* Size of this structure */
    uint32_t sched_policy;      /* Policy (SCHED_*) */
    uint64_t sched_flags;       /* Flags */
    int32_t  sched_nice;        /* Nice value (SCHED_OTHER, SCHED_BATCH) */
    uint32_t sched_priority;    /* Static priority (SCHED_FIFO, SCHED_RR) */
    /* Remaining fields are for SCHED_DEADLINE */
    uint64_t sched_runtime;
    uint64_t sched_deadline;
    uint64_t sched_period;
  };
#endif /* sched_attr */

////////////////////////////////////////////////////////////////

#ifndef statx_timestamp
  struct statx_timestamp
  {
    __s64 tv_sec;    /* Seconds since the Epoch (UNIX time) */
    __u32 tv_nsec;   /* Nanoseconds since tv_sec */
  };
#endif

////////////////////////////////////////////////////////////////

#ifndef statx
  struct statx
  {
    __u32 stx_mask;        /* Mask of bits indicating
                              filled fields */
    __u32 stx_blksize;     /* Block size for filesystem I/O */
    __u64 stx_attributes;  /* Extra file attribute indicators */
    __u32 stx_nlink;       /* Number of hard links */
    __u32 stx_uid;         /* User ID of owner */
    __u32 stx_gid;         /* Group ID of owner */
    __u16 stx_mode;        /* File type and mode */
    __u64 stx_ino;         /* Inode number */
    __u64 stx_size;        /* Total size in bytes */
    __u64 stx_blocks;      /* Number of 512B blocks allocated */
    __u64 stx_attributes_mask;
                          /* Mask to show what's supported
                              in stx_attributes */

    /* The following fields are file timestamps */
    struct statx_timestamp stx_atime;  /* Last access */
    struct statx_timestamp stx_btime;  /* Creation */
    struct statx_timestamp stx_ctime;  /* Last status change */
    struct statx_timestamp stx_mtime;  /* Last modification */

    /* If this file represents a device, then the next two
      fields contain the ID of the device */
    __u32 stx_rdev_major;  /* Major ID */
    __u32 stx_rdev_minor;  /* Minor ID */

    /* The next two fields contain the ID of the device
      containing the filesystem where the file resides */
    __u32 stx_dev_major;   /* Major ID */
    __u32 stx_dev_minor;   /* Minor ID */

    __u64 stx_mnt_id;      /* Mount ID */

    /* Direct I/O alignment restrictions */
    __u32 stx_dio_mem_align;
    __u32 stx_dio_offset_align;
  };
#endif

////////////////////////////////////////////////////////////////

#ifndef io_sqring_offsets
  struct io_sqring_offsets
  {
    __u32 head;
    __u32 tail;
    __u32 ring_mask;
    __u32 ring_entries;
    __u32 flags;
    __u32 dropped;
    __u32 array;
    __u32 resv1;
    __u64 user_addr;
  };
#endif

////////////////////////////////////////////////////////////////

#ifndef io_cqring_offsets
  struct io_cqring_offsets
  {
    __u32 head;
    __u32 tail;
    __u32 ring_mask;
    __u32 ring_entries;
    __u32 overflow;
    __u32 cqes;
    __u32 flags;
    __u32 resv1;
    __u64 user_addr;
  };
#endif

////////////////////////////////////////////////////////////////

#ifndef io_uring_params
  struct io_uring_params
  {
    __u32 sq_entries;
    __u32 cq_entries;
    __u32 flags;
    __u32 sq_thread_cpu;
    __u32 sq_thread_idle;
    __u32 features;
    __u32 wq_fd;
    __u32 resv[3];
    struct io_sqring_offsets sq_off;
    struct io_cqring_offsets cq_off;
  };
#endif

////////////////////////////////////////////////////////////////

#ifndef clone_args
  struct clone_args
  {
    uint64_t flags;        /* Flags bit mask */
    uint64_t pidfd;        /* Where to store PID file descriptor
                        (int *) */
    uint64_t child_tid;    /* Where to store child TID,
                        in child's memory (pid_t *) */
    uint64_t parent_tid;   /* Where to store child TID,
                        in parent's memory (pid_t *) */
    uint64_t exit_signal;  /* Signal to deliver to parent on
                        child termination */
    uint64_t stack;        /* Pointer to lowest byte of stack */
    uint64_t stack_size;   /* Size of stack */
    uint64_t tls;          /* Location of new TLS */
    uint64_t set_tid;      /* Pointer to a pid_t array
                        (since Linux 5.5) */
    uint64_t set_tid_size; /* Number of elements in set_tid
                        (since Linux 5.5) */
    uint64_t cgroup;       /* File descriptor for target cgroup
                        of child (since Linux 5.7) */
  };
#endif

////////////////////////////////////////////////////////////////

#ifndef cachestat_range
  struct cachestat_range
  {
    __u64 off;
    __u64 len;
  };
#endif

////////////////////////////////////////////////////////////////

#ifndef cachestat
  struct cachestat
  {
  __u64 nr_cache;
  __u64 nr_dirty;
  __u64 nr_writeback;
  __u64 nr_evicted;
  __u64 nr_recently_evicted;
  };
#endif

#endif /* _ELF_DYNAMIC_INFO_ */