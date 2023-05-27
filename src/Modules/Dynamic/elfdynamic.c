#include <signal.h>
#include "elfdynamic.h"

int8_t launchTraceProgram(ELF_EXECUTABLE_T * executableHandle, int argc, char** argv, char** envp)
{
  struct ptrace_syscall_info syscallInfo = {0};
  struct user_regs_struct regs = {0};
  char** childArgs   = NULL;
  long syscallNumber = 0;
  int status         = 0;
  pid_t pid          = 0;
  int8_t err         = ERR_NONE;

  if(executableHandle == NULL)
  {
    #ifdef DEBUG
    perror("ERROR null parameter passed to launchTraceProgram()");
    #endif
    return ERR_NULL_ARGUMENT;
  }

  if(argc > 2)
  {
    childArgs = malloc(argc - 2);
    if(childArgs == NULL)
    {
      #ifdef DEBUG
      perror("ERROR allocating memory in launchTraceProgram()");
      #endif
      err = ERR_MEMORY_ALLOCATION_FAILED;
      goto cleanup;
    }
    for(int i = 2; i < argc; i++)
    {
      childArgs[i-2] = argv[i];
    }
  }

  if( (pid = fork()) < 0)
  {
    #ifdef DEBUG
    perror("ERROR unable to fork process in launchTraceProgram()");
    #endif
    err = ERR_PROCESS_OPERATION_FAILED;
    goto cleanup;
  }

  /*
   * Child process tells the parent it wants to be traced
   * and executes the new program so we can trace its execution.
   */
  if(pid == 0)
  {
    printf("Calling PTRACE_TRACEME\n");
    if(ptrace(PTRACE_TRACEME, pid, NULL, NULL) < 0)
    {
      #ifdef DEBUG
      perror("ERROR CALLING: PTRACE_TRACEME in launchTraceProgram()");
      #endif
      err = ERR_PROCESS_OPERATION_FAILED;
      goto cleanup;
    }

    printf("Starting new process\n");
    execl(childArgs[0], childArgs, envp);

    err = ERR_NONE;
    goto cleanup; // Cleanup after child process finishes executing traced process.
  }
  else
  {
    wait(&status);
    syscallNumber = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    printf("Syscall number: %d\n", regs.rax);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
  }
  

  cleanup:
  free(childArgs);
  return err;
}



















static int8_t attachToProcess(pid_t pid)
{


  if(ptrace(PTRACE_ATTACH, pid, 0, 0) == -1)
  {
    #ifdef DEBUG
    perror("ERROR CALLING: ptrace(PTRACE_ATTACH, pid, 0, 0)");
    #endif
    return ERR_UNKNOWN;
  }
  return ERR_NONE;
}

static int8_t detachFromProcess(pid_t pid)
{


  if(ptrace(PTRACE_DETACH, pid, 0, 0) == -1)
  {
    #ifdef DEBUG
    perror("ERROR CALLING: ptrace(PTRACE_DETACH, pid, 0, 0)");
    #endif
    return ERR_UNKNOWN;
  }
  return ERR_NONE;
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

    return FALSE;
  }

  return TRUE;
}


int8_t dump_memory(pid_t pid, uint64_t startAddr, uint64_t uCount)
{
  char* pMem;
  uint64_t tmp;
  uint64_t iterations;

  if(uCount == 0) { return ERR_UNKNOWN; }

  tmp = uCount / 8; /* Divide by intel word size rounding down */
  iterations = ((float)(tmp * 8) == uCount) ? tmp : (uint64_t)(tmp) + 1; /* Check tmp is integer value. */
  

  if( (pMem = malloc(uCount)) == NULL)
  {
    perror("ERROR allocating memory for read.");
    return ERR_UNKNOWN;
  }

  /* Print top of grid. */
  PRINT_GRID_TOP;

  for(uint64_t i = 0; i < iterations; ++i)
  {
    if(ptrace(PTRACE_PEEKDATA, pid, startAddr + (i*8), pMem + (i*8)) == ERR_UNKNOWN)
    {
      perror("ERROR calling PTRACE_PEEKDATA");
      return ERR_UNKNOWN;
    }
    printf("0x%016x %02x %02x %02x %02x, %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", startAddr + (i*8), \
      *(pMem + (i*8)), *(pMem + (i*8) + 1), *(pMem + (i*8) + 2), *(pMem + (i*8) + 3), *(pMem + (i*8) + 4), \
      *(pMem + (i*8) + 5), *(pMem + (i*8) + 6), *(pMem + (i*8) + 7), *(pMem + (i*8) + 8), *(pMem + (i*8) + 9), \
      *(pMem + (i*8) + 10), *(pMem + (i*8) + 11), *(pMem + (i*8) + 12), *(pMem + (i*8) +13), *(pMem + (i*8) + 14), \
      *(pMem + (i*8) + 15));
  }

  free(pMem); /* Deallocate memory. */
  return ERR_NONE;
}