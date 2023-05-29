#include "elfdynamic.h"

int8_t launchTraceProgram(ELF_EXECUTABLE_T * executableHandle, int childArgc, char** childArgs, char** envp)
{
  int8_t err         = ERR_NONE;

  if(executableHandle == NULL)
  {
    #ifdef DEBUG
    perror("ERROR null parameter passed to launchTraceProgram()");
    #endif
    return ERR_NULL_ARGUMENT;
  }

  switch (executableHandle->elfHandle64.ehdr->e_ident[EI_CLASS])
  {
    case ELFCLASS64:
      err = launchTraceProgram64((ELF64_EXECUTABLE_HANDLE_T *) executableHandle, childArgc, childArgs, envp);
      break;
    
    case ELFCLASS32:
      break;

    case ELFCLASSNONE:
    default:
      return ERR_INVALID_ARGUMENT;
  }

  
  
  return ERR_NONE;
}

static int8_t launchTraceProgram64(ELF64_EXECUTABLE_HANDLE_T * executableHandle, int childArgc, char** childArgv, char** envp)
{
  struct ptrace_syscall_info syscallInfo = {0};
  struct user_regs_struct regs = {0};
  long syscallNumber = 0;
  int status         = 0;
  int8_t executing   = TRUE;
  int8_t err         = ERR_NONE;

  if( (executableHandle->pid = fork()) < 0)
  {
    #ifdef DEBUG
      perror("ERROR fork() failed in launchTraceProgram()");
      #endif
      return ERR_PROCESS_OPERATION_FAILED;
  }

  if(executableHandle->pid == 0)
  {
    if( (ptrace(PTRACE_TRACEME, executableHandle->pid, NULL, NULL)) < 0)
    {
      #ifdef DEBUG
      perror("ERROR ptrace_traceme failed in launchTraceProgram()");
      #endif
      return ERR_TRACE_OPERATION_FAILED;
    }
    execl(executableHandle->fileHandle.path, childArgv, NULL);
    return ERR_NONE;
  }

  while(executing)
  {
    wait(&status);
    if(WIFEXITED(status))
    {
      executing = FALSE;
    }
    else
    {
      syscallNumber = ptrace(PTRACE_PEEKUSER,
                        executableHandle->pid, 8 * ORIG_RAX,
                        NULL);
      printf("The child made a "
              "system call %ld\n", syscallNumber);
      ptrace(PTRACE_CONT, executableHandle->pid, NULL, NULL);
    }
    
  }
}