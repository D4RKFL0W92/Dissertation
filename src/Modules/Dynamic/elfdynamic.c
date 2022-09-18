#include "elfdynamic.h"

static int8_t attachToProcess(pid_t pid)
{
    #ifdef DEBUG
    const char *func_name = "attachToProcess()";
    #endif

    if(ptrace(PTRACE_ATTACH, pid, 0, 0) == -1)
    {
        #ifdef DEBUG
        perror("ERROR CALLING: ptrace(PTRACE_ATTACH, pid, 0, 0)");
        #endif
        logEvent(LOG_FILE, func_name, "ERROR CALLING: ptrace(PTRACE_ATTACH, pid, 0, 0)");
        return FAILED;
    }
    return SUCCESS;
}

static int8_t detachFromProcess(pid_t pid)
{
    #ifdef DEBUG
    const char *func_name = "detachFromProcess()";
    #endif

    if(ptrace(PTRACE_DETACH, pid, 0, 0) == -1)
    {
        #ifdef DEBUG
        perror("ERROR CALLING: ptrace(PTRACE_DETACH, pid, 0, 0)");
        #endif
        logEvent(LOG_FILE, func_name, "ERROR CALLING: ptrace(PTRACE_DETACH, pid, 0, 0)");
        return FAILED;
    }
    return SUCCESS;
}

static int8_t getRegisterValues(int pid, struct user_regs_struct* regs)
{

    const char *func_name = "getRegisterValues()";
 
    struct user_regs_struct* registers; 
    
    if(ptrace(PTRACE_GETREGS, pid, NULL, regs) == -1)
    {
        #ifdef DEBUG
        perror("ERROR CALLING: ptrace(PTRACE_GETREGS, pid, NULL, registers)");
        #endif

        logEvent(LOG_FILE, func_name, "ERROR CALLING: ptrace(PTRACE_GETREGS, pid, NULL, registers)");
        return FALSE;
    }

    return TRUE;
}

int16_t beginProcessTrace(const char* p_procName, int argc, char** argv, char** envp)
{
    struct user_regs_struct registers;
    pid_t pid;
    enum BITS arch;
    uint64_t exec_sz;
    uint8_t* p_mem;
    int child_state;
    
    if( (p_mem = mapELFToMemory(p_procName, &arch, &exec_sz)) == NULL)
    {
        #ifdef DEGUG
        perror("ERROR: Cannot map executable to memory.")
        #endif
        return FAILED;
    }
        

    if((pid = fork()) < 0)
    {
        #ifdef DEBUG
        perror("ERROR forking process.");
        #endif
        return FAILED;
    }

    if(pid == 0) /* Child process */
    {
        if(ptrace(PTRACE_TRACEME, pid, NULL, NULL) < 0)
        {
            #ifdef DEBUG
            perror("ERROR calling PTRACE_TRACEME");
            #endif
            return FAILED;
        }
        // execve the process we intend to trace.
        execve(p_procName, argv, envp);
    }

    
    else
    {
        wait(&child_state); /* Wait for state change of child process. */

        // if(attachToProcess(pid) == FAILED)
        // {
        //     #ifdef DEBUG
        //     perror("ERROR: Cannot attach to process.");
        //     #endif
        //     return FAILED;
        // }

        // if(getRegisterValues(pid, &registers) == FALSE)
        // {
        //     #ifdef DEBUG
        //     perror("ERROR: Cannot get register values.");
        //     #endif
        //     return FAILED;
        // }

        // printf("rip: 0x%08x", registers.rip);
    }

    return TRUE;
}



void test_getRegisterValues(pid_t pid)
{
    struct user_regs_struct regs;

    getRegisterValues(pid, &regs);
}