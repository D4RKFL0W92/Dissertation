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
#include <signal.h>
#include <dirent.h>
#include <mqueue.h>
#include <sys/sem.h>
#include <sys/reg.h>
#include <sys/time.h>
#include <sys/swap.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/timex.h>
#include <sys/xattr.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/ptrace.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <linux/futex.h>
#include <linux/types.h>
#include <linux/kexec.h>
#include <linux/ioprio.h>
#include <linux/ptrace.h>
#include <linux/keyctl.h>
#include <linux/aio_abi.h>
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
#endif

#endif