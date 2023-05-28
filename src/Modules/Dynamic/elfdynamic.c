#include <signal.h>
#include "elfdynamic.h"

int8_t launchTraceProgram(ELF_EXECUTABLE_T * executableHandle, int childArgc, char** childArgs, char** envp)
{
  struct ptrace_syscall_info syscallInfo = {0};
  struct user_regs_struct regs = {0};
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

  for(int i = 0; i < childArgc; i++)
  {
    printf("Arg %d: %s\n", i, childArgs[i]);
  }

  if( (pid = fork()) < 0)
  {
    return ERR_PROCESS_OPERATION_FAILED;
  }

  if(pid == 0)
  {
    ptrace(PTRACE_TRACEME, pid, NULL, NULL);
    execl(executableHandle->elfHandle64.fileHandle.path, NULL);
  }
  else
  {
    wait(NULL);
    syscallNumber = ptrace(PTRACE_PEEKUSER,
                      pid, 8 * ORIG_RAX,
                      NULL);
    printf("The child made a "
            "system call %ld\n", syscallNumber);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
  }
  
  return ERR_NONE;
}