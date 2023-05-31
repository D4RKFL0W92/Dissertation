#include "elfdynamic.h"

static void * readStringFromProcessMemory64(ELF64_EXECUTABLE_HANDLE_T * executableHandle, uint64_t offset)
{
  uint16_t allocationSize = 40;
  void *   data       = NULL;
  char *   pChar      = NULL;
  int8_t   err        = ERR_NONE;
  long     wordRead   = 0;
  uint8_t  nullRead   = FALSE;
  uint8_t  charCount  = 0;
  uint8_t  cpySize    = 0;

  if( (data = malloc(allocationSize)) == NULL)
  {
    return NULL;
  }
  memset(data, 0, allocationSize);

  while(nullRead == FALSE)
  {
    
    wordRead = 0;
    wordRead = ptrace(PTRACE_PEEKDATA, executableHandle->pid, offset + charCount * sizeof(long), NULL);
    pChar = (char *)& wordRead;
    for(uint8_t i = 0; i < sizeof(long); i++)
    {
      if(*pChar == '\0')
      {
        cpySize = i;
      }
      else
      {
        cpySize = sizeof(long);
      }
    }

    memcpy(data + charCount * sizeof(long), &wordRead, cpySize);

    charCount += sizeof(long);
    if(charCount >= allocationSize)
    {
      realloc(data, (allocationSize + 40));
      memset(data + allocationSize, 0, allocationSize);
      allocationSize += 40;
    }
  }
  return data;
}

static void * readProcessMemory64(ELF64_EXECUTABLE_HANDLE_T * executableHandle, uint64_t offset, uint64_t uCount)
{
  void *   data       = NULL;
  uint16_t iterations = 0;
  int8_t   err        = ERR_NONE;
  long     wordRead   = 0;
  // Is this calculation correct.
  iterations = (uCount % sizeof(long) == 0) ? uCount / sizeof(long) : uCount / sizeof(long) + 1;

  if( (data = malloc(uCount)) == NULL)
  {
    return NULL;
  }
  memset(data, 0, uCount);

  for(uint16_t i = 0; i < iterations; i++)
  {
    wordRead = 0;
    wordRead = ptrace(PTRACE_PEEKDATA, executableHandle->pid, offset + i * sizeof(long), NULL);
    memcpy(data + i * sizeof(long), &wordRead, sizeof(long));
  }

  return data;
}

static int printSyscallInfo64(ELF64_EXECUTABLE_HANDLE_T * executableHandle)
{
  char* tmpBuffer = NULL;

  switch(executableHandle->regs.orig_rax)
  {
    case SYS_read:
      tmpBuffer = readProcessMemory64(executableHandle,
                                      executableHandle->regs.rsi,
                                      executableHandle->regs.rdx);
      printf("read(fd=%d, buffer=%s, count=%d)\n", executableHandle->regs.rdi,
                                                   tmpBuffer,
                                                   executableHandle->regs.rdx);
      break; /*SYS_read*/

    case SYS_write:
      if(executableHandle->regs.rdx > 0)
      {
        tmpBuffer = readProcessMemory64(executableHandle, executableHandle->regs.rsi,
                                                          executableHandle->regs.rdx);
        tmpBuffer = realloc(tmpBuffer, executableHandle->regs.rdx + 1);
        tmpBuffer[executableHandle->regs.rdx] = '\0'; // Remove extra \n that may be output by command.
      }
      printf("write(fd=%d, buffer=\"%s\", count=%d)\n", executableHandle->regs.rdi,
                                                        tmpBuffer,
                                                        executableHandle->regs.rdx);
      break; /*SYS_write*/

    case SYS_open:
      /* TODO: Test if this works (print string from processSpace[rdi]). */
      printf("open(path=%s)\n", executableHandle->regs.rdi);
      break; /*SYS_open*/

    case SYS_close:
      printf("close(fd=%d)\n", executableHandle->regs.rdi);
      break; /*SYS_close*/

    case SYS_stat:
    case SYS_lstat:
      printf("stat(path=\"%s\", struct=0x%08x)\n", executableHandle->regs.rdi,
                                                   executableHandle->regs.rsi);
      break; /*stat/lstat*/

    case SYS_fstat:
      printf("fstat(fd=%d, struct=0x%08x)\n", executableHandle->regs.rdi,
                                              executableHandle->regs.rsi);
      break;

    case SYS_poll:
      printf("poll(pollfd=%p, nfds=%d, timeout=%d)\n", executableHandle->regs.rdi,
                                                       executableHandle->regs.rsi,
                                                       executableHandle->regs.rdx);
      break; /*SYS_poll*/






    case SYS_execve:
      // TODO:Find a way to extract the filename to run
      // all registers except ORIG_RAX are zero. How can
      // we extract all arguments???
      printf("execve()\n");
      break; /*SYS_execve*/

  }
  free(tmpBuffer);
  return ERR_NONE;
}

static int8_t launchTraceProgram64(ELF64_EXECUTABLE_HANDLE_T * executableHandle, int childArgc, char** childArgv, char** envp)
{
  struct ptrace_syscall_info syscallInfo = {0};
  long syscallNumber = 0;
  int status         = 0;
  int8_t err         = ERR_NONE;

  executableHandle->isExecuting = TRUE;
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

  do
  {
    wait(&status);
    if(WIFEXITED(status))
    {
      executableHandle->isExecuting = FALSE;
    }
    else
    {
      /* Get the syscall RAX value. */
      ptrace(PTRACE_GETREGS, executableHandle->pid,
                      NULL, &executableHandle->regs);
                        
      printf("Entering sycall number: %ld\n", executableHandle->regs.orig_rax);
      printSyscallInfo64(executableHandle);


      /* Continue to the next syscall. */        
      ptrace(PTRACE_SYSCALL, executableHandle->pid, NULL, NULL);
    }

  } while(executableHandle->isExecuting);

  return ERR_NONE;
}

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

