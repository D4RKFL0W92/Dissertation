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
#include <linux/ptrace.h>
#include "../../Logging/logging.h"
#include "../../Types/turtle_types.h"
#include "../ELFinfo/elfinfo.h"


int8_t launchTraceProgram(ELF_EXECUTABLE_T * executableHandle, int childArgc, char** childArgv, char** envp);
static int8_t launchTraceProgram64(ELF64_EXECUTABLE_HANDLE_T * executableHandle, int childArgc, char** childArgv, char** envp);
static int8_t launchTraceProgram32(ELF_EXECUTABLE_T * executableHandle, int childArgc, char** childArgv, char** envp);

static int8_t detachFromProcess(pid_t pid);
static int8_t getRegisterValues(int pid, struct user_regs_struct* regs);

int16_t beginProcessTrace(const char* p_procName, int argc, char** argv, char** envp);

void test_getRegisterValues(pid_t pid);
int8_t dump_memory(pid_t pid, uint64_t startAddr, uint64_t uCount);

#endif