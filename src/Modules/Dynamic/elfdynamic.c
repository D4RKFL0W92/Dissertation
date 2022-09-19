#include <signal.h>
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
        if(wait(&child_state) == FAILED) /* Wait for state change of child process. */
        {
            perror("ERROR calling wait from parent.");
            exit(FAILED);
        }

        do
        {
            if(ptrace(PTRACE_GETREGS, pid, 0, &registers) != 0)
            {
                perror("ERROR getting register values.");
                exit(-1);
            }

            printf("RIP:\t0x%016x\n", registers.rip);
            
            if(ptrace(PTRACE_SINGLESTEP, pid, 0, 0) != 0)
            {
                perror("ERROR calling PTRACE_SINGLESTEP on child process.");
                exit(-1);
            }

            wait(&child_state);

        } while (child_state != SIGCHLD || child_state != SIGTRAP);
        
    }

    return TRUE;
}

int8_t dump_memory(pid_t pid, uint64_t startAddr, uint64_t uCount)
{
    char* pMem;
    uint64_t tmp;
    uint64_t iterations;

    if(uCount == 0) { return FAILED; }

    tmp = uCount / 8; /* Divide by intel word size rounding down */
    iterations = \
        ((float)(tmp * 8) == uCount) ? tmp : (uint64_t)(tmp) + 1; /* Check tmp is integer value. */
    

    if( (pMem = malloc(uCount)) == NULL)
    {
        perror("ERROR allocating memory for read.");
        return FAILED;
    }

    /* Print top of grid. */
    printf("                  0   2   3   4   5   6   7   8   9   A   B   C   D   E   F\n");

    for(uint64_t i = 0; i < iterations; ++i)
    {
        if(ptrace(PTRACE_PEEKDATA, pid, startAddr + (i*8), pMem + (i*8)) == FAILED)
        {
            perror("ERROR calling PTRACE_PEEKDATA");
            return FAILED;
        }
        printf("0x%016x %02x %02x %02x %02x, %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", startAddr + (i*8), \
            *(pMem + (i*8)), *(pMem + (i*8) + 1), *(pMem + (i*8) + 2), *(pMem + (i*8) + 3), *(pMem + (i*8) + 4), \
            *(pMem + (i*8) + 5), *(pMem + (i*8) + 6), *(pMem + (i*8) + 7), *(pMem + (i*8) + 8), *(pMem + (i*8) + 9), \
            *(pMem + (i*8) + 10), *(pMem + (i*8) + 11), *(pMem + (i*8) + 12), *(pMem + (i*8) +13), *(pMem + (i*8) + 14), \
            *(pMem + (i*8) + 15));
    }

    free(pMem); /* Deallocate memory. */
    return SUCCESS;
}