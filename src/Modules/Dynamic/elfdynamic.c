#include "elfdynamic.h"

struct user_regs_struct* getRegisterValues(int pid)
{
    #ifdef DEBUG
    const char *func_name;
    #endif
    struct user_regs_struct* registers;

    if(ptrace(PTRACE_ATTACH, pid, 0, 0) == -1)
    {
        #ifdef DEBUG
        logEvent(LOG_FILE, func_name, "ptrace(PTRACE_ATTACH, pid, 0, 0)");
        #endif
        return NULL;
    }
        
    
    if(ptrace(PTRACE_GETREGS, pid, NULL, registers) == -1)
        return NULL;

    return registers;
}