/*
 * Copywrite: 2023 Calum Dawson calumjamesdawson@gmail.com
*/

#ifndef _ELF_DYNAMIC_INFO_
#define _ELF_DYNAMIC_INFO_

#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/ptrace.h>
#include "../Headers/elftypes.h"
#include "../../Logging/logging.h"
#include "../../Types/turtle_types.h"
#include "../ELFinfo/elfinfo.h"

int8_t readStringFromProcessMemory(pid_t pid, uint64_t offset, char** pStr);
int8_t readProcessMemoryFromPID(pid_t pid, const void * offset, void * dstAddr, uint64_t uCount);

int8_t launchTraceProgram(ELF_EXECUTABLE_T * executableHandle, int childArgc, char** childArgv, char** envp);

int8_t mapELF32ToHandleFromProcessMemory(void ** pMem, ELF32_EXECUTABLE_HANDLE_T ** elfHandle);
int8_t mapELF64ToHandleFromProcessMemory(void ** pMem, ELF64_EXECUTABLE_HANDLE_T ** elfHandle, const uint64_t uCount);

#ifdef UNITTEST
void elfDynamicTestSuite();
#endif /* UNITTEST */

#endif