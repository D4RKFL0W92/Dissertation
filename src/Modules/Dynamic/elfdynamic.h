#ifndef _ELF_DYNAMIC_INFO_
#define _ELF_DYNAMIC_INFO_

#include <stdlib.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "../../Logging/logging.h"
#include "../../Types/turtle_types.h"
#include "../ELFinfo/elfinfo.h"

#define PRINT_GRID_TOP printf("                  0   2   3   4   5   6   7   8   9   A   B   C   D   E   F\n")
#define PRINT_GRID_ROW(startAddr, pMem, i) \
        printf("0x%016x %02x %02x %02x %02x, %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", startAddr + (i*8), \
            *(pMem + (i*8)), *(pMem + (i*8) + 1), *(pMem + (i*8) + 2), *(pMem + (i*8) + 3), *(pMem + (i*8) + 4), \
            *(pMem + (i*8) + 5), *(pMem + (i*8) + 6), *(pMem + (i*8) + 7), *(pMem + (i*8) + 8), *(pMem + (i*8) + 9), \
            *(pMem + (i*8) + 10), *(pMem + (i*8) + 11), *(pMem + (i*8) + 12), *(pMem + (i*8) +13), *(pMem + (i*8) + 14), \
            *(pMem + (i*8) + 15))

int8_t launchTraceProgram(ELF_EXECUTABLE_T * executableHandle, int argc, char** argv, char** envp);

static int8_t detachFromProcess(pid_t pid);
static int8_t getRegisterValues(int pid, struct user_regs_struct* regs);

int16_t beginProcessTrace(const char* p_procName, int argc, char** argv, char** envp);

void test_getRegisterValues(pid_t pid);
int8_t dump_memory(pid_t pid, uint64_t startAddr, uint64_t uCount);

#endif