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
#include <utime.h>
#include <sched.h>
#include <signal.h>
#include <sys/sem.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <sys/timex.h>
#include <sys/resource.h>
#include <sys/swap.h>
#include <sys/reboot.h>
#include <sys/xattr.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/ptrace.h>
#include <linux/aio_abi.h>
#include <linux/futex.h>
#include <linux/types.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>
#include "../Headers/elftypes.h"
#include "../../Logging/logging.h"
#include "../../Types/turtle_types.h"
#include "../ELFinfo/elfinfo.h"

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

#endif