#include <signal.h>
#include "elfdynamic.h"

int8_t launchTraceProgram(ELF_EXECUTABLE_T * executableHandle, int argc, char** argv, char** envp)
{
  char** childArgs = NULL;
  pid_t pid = 0;
  int status = 0;
  int8_t err = ERR_NONE;

  if(executableHandle == NULL)
  {
    #ifdef DEBUG
    perror("ERROR CALLING: ptrace(PTRACE_ATTACH, pid, 0, 0)");
    #endif
    return ERR_NULL_ARGUMENT;
  }

  if(argc > 2)
  {
    childArgs = malloc(argc - 2);
    if(childArgs == NULL)
    {
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
    err = ERR_PROCESS_OPERATION_FAILED;
    goto cleanup;
  }

  if(pid == 0)
  {
    if(ptrace(PTRACE_TRACEME, pid, NULL, NULL) < 0)
    {
      err = ERR_PROCESS_OPERATION_FAILED;
      goto cleanup;
    }
    execve(childArgs[0], childArgs, envp);
    goto cleanup; // Cleanup after child process finishes executing traced process.
  }

  wait(&status);

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