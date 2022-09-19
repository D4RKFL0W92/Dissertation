#ifndef _ELF_DYNAMIC_INFO_
#define _ELF_DYNAMIC_INFO_

#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <stdint.h>
#include <sys/wait.h>

#include "../../Logging/logging.h"
#include "../../Types/turtle_types.h"
#include "../ELFinfo/elfinfo.h"

/*
    Attaches the calling process as a tracer to the given PID that
    becomes the tracee. (Sends a SIGSTOP to the tracee process).

    Param_1: The process ID (PID) of the tracee thread.
    Return:  Returns FAILED or SUCCESS (1 / -1) Macro.
*/
static int8_t attachToProcess(pid_t pid);
static int8_t detachFromProcess(pid_t pid);
static int8_t getRegisterValues(int pid, struct user_regs_struct* regs);

int16_t beginProcessTrace(const char* p_procName, int argc, char** argv, char** envp);

void test_getRegisterValues(pid_t pid);
int8_t dump_memory(pid_t pid, uint64_t startAddr, uint64_t uCount);

#endif