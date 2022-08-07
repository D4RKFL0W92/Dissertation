#include "elfdynamic.h"

struct user_regs_struct* getRegisterValues(int pid)
{
    struct user_regs_struct* registers;

    if(ptrace(PTRACE_ATTACH, pid, 0, 0) == -1)
        return NULL;
    
    if(ptrace(PTRACE_GETREGS, pid, NULL, registers) == -1)
        return NULL;

    return registers;
}