#include "elfdynamic.h"

static int8_t readStringFromProcessMemory64(ELF64_EXECUTABLE_HANDLE_T * executableHandle, uint64_t offset, char** pStr)
{
  uint16_t allocationSize = 40;
  char *   data       = NULL;
  char *   pChar      = NULL;
  int8_t   err        = ERR_NONE;
  long     wordRead   = 0;
  uint8_t  nullRead   = FALSE;
  uint8_t  charCount  = 0;
  uint8_t  cpySize    = 0;

  if( (data = malloc(allocationSize)) == NULL)
  {
    return ERR_MEMORY_ALLOCATION_FAILED;
  }
  memset(data, 0, allocationSize);

  while(nullRead == FALSE)
  {
    
    wordRead = 0;
    wordRead = ptrace(PTRACE_PEEKDATA, executableHandle->pid, offset + charCount, NULL);
    pChar = (char *)& wordRead;
    for(uint8_t i = 0; i < sizeof(long); i++)
    {
      if(*pChar++ == '\0')
      {
        cpySize = i;
        nullRead = TRUE;
        break;
      }
      else
      {
        cpySize = sizeof(long);
      }
    }

    memcpy(data + charCount, &wordRead, cpySize);

    charCount += sizeof(long);
    if(charCount >= allocationSize && nullRead == FALSE)
    {
      realloc(data, (allocationSize + 40));
      memset(data + allocationSize, 0, allocationSize);
      allocationSize += 40;
    }
  }
  (*pStr) = data;
  return ERR_NONE;
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

static int8_t printSyscallInfoElf64(ELF64_EXECUTABLE_HANDLE_T * executableHandle)
{
  struct ptrace_syscall_info syscallInfo = {0};
  char* tmpBuffer = NULL;
  int8_t err = ERR_NONE;

  switch(executableHandle->regs.orig_rax)
  {
    case SYS_read:
      tmpBuffer = readProcessMemory64(executableHandle,
                                      executableHandle->regs.rsi,
                                      executableHandle->regs.rdx);

      printf("read(fd=%d, buffer=\"%s\", count=%d)\n",
        executableHandle->regs.rdi,
        tmpBuffer,
        executableHandle->regs.rdx);
      break; /*SYS_read*/

    case SYS_write:
      if(executableHandle->regs.rdx > 0)
      {
        tmpBuffer = readProcessMemory64(executableHandle,
          executableHandle->regs.rsi,
          executableHandle->regs.rdx);

        tmpBuffer = realloc(tmpBuffer, executableHandle->regs.rdx + 1);
        tmpBuffer[executableHandle->regs.rdx] = '\0'; // Remove extra \n that may be output by command.
      }
      printf("write(fd=%d, buffer=\"%s\", count=%d)\n",
        executableHandle->regs.rdi,
        tmpBuffer,
        executableHandle->regs.rdx);
      break; /*SYS_write*/

    case SYS_open:
      err = readStringFromProcessMemory64(executableHandle, executableHandle->regs.rdi, &tmpBuffer);
      printf("open(path=%s)\n", tmpBuffer);
      break; /*SYS_open*/

    case SYS_close:
      printf("close(fd=%d)\n", executableHandle->regs.rdi);
      break; /*SYS_close*/

    case SYS_stat:
    case SYS_lstat:
      err = readStringFromProcessMemory64(executableHandle, executableHandle->regs.rdi, &tmpBuffer);

      printf("stat(path=\"%s\", struct=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);
      break; /*stat/lstat*/

    case SYS_fstat:
      printf("fstat(fd=%d, struct=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);
      break;

    case SYS_poll:
      printf("poll(pollfd=%p, nfds=%d, timeout=%d)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_poll*/

    case SYS_lseek:
      printf("lseek(fd=%d, offset=%p, whence=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_lseek*/

    case SYS_mmap:
      printf("mmap(address=0x%08x, length=%d, protections=0x%08x, flags=0x%08x, " \
        "fd=%d, offset=0x%08x)\n",
            executableHandle->regs.rdi,
            executableHandle->regs.rsi,
            executableHandle->regs.rdx,
            executableHandle->regs.r10,
            executableHandle->regs.r8,
            executableHandle->regs.r9);
      break; /*SYS_mmap*/

    case SYS_mprotect:
      printf("mprotect(start=%p, size=0x%08x, protections=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_mprotect*/

    case SYS_munmap:
      printf("munmap(address=%p, size=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);
      break; /*SYS_munmap*/

    case SYS_brk:
      printf("brk(brk=0x%08x)\n", executableHandle->regs.rdi);
      break; /*SYS_brk*/

    case SYS_rt_sigaction:
      printf("rt_sigaction(signum=%d, sig-new-action=0x%08x, " \
             "sig-old-action=0x%08x, size=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx,
              executableHandle->regs.r10);
      break; /*SYS_rt_sigaction*/

    case SYS_rt_sigprocmask:
      printf("rt_sigprocmask(how=%d, sig-new-set=0x%08x, " \
            "sig-old-set=0x%08x, size=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx,
              executableHandle->regs.r10);
      break; /*SYS_rt_sigprocmask*/

    case SYS_rt_sigreturn:
      printf("rt_sigreturn()\n");
      break; /*SYS_rt_sigreturn*/

    case SYS_ioctl:
      printf("ioctl(fd=%d, cmd=%d, arg=%ld)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_ioctl*/

    case SYS_pread64:
      /*TODO: Is it worth printing the bytes that are being read?*/
      tmpBuffer = readProcessMemory64(executableHandle, executableHandle->regs.rsi, executableHandle->regs.rdx);
      printf("pread64(fd=%d, buff=%p, count=0x%08x, position=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10);
      break; /*SYS_pread64*/

    case SYS_pwrite64:
      tmpBuffer = readProcessMemory64(executableHandle, executableHandle->regs.rsi, executableHandle->regs.rdx);
      printf("pwrite64(fd=%d, buff=%p, count=0x%08x, position=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10);
      break; /*SYS_pwrite64*/

    case SYS_readv:
      tmpBuffer = readProcessMemory64(executableHandle, executableHandle->regs.rsi, executableHandle->regs.rdx);
      printf("readv(fd=%d, iovec=%p, vec-len=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_readv*/

    case SYS_writev:
      tmpBuffer = readProcessMemory64(executableHandle, executableHandle->regs.rsi, executableHandle->regs.rdx);
      printf("writev(fd=%d, iovec=%p, vec-len=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_writev*/

    case SYS_access:
      err = readStringFromProcessMemory64(executableHandle, executableHandle->regs.rdi, &tmpBuffer);
      printf("access(filename=%s, mode=0x%08x)\n",
        tmpBuffer,
        executableHandle->regs.rsi);
      break; /*SYS_access*/


///////////////////////////////////////////////////////////////////////////////
    case SYS_execve:
      // TODO:Find a way to extract the filename to run
      // all registers except ORIG_RAX are zero. How can
      // we extract all arguments???
      printf("execve()\n");
      break; /*SYS_execve*/

  }
  free(tmpBuffer);
  return err;
}

static int8_t launchSyscallTraceElf64(ELF64_EXECUTABLE_HANDLE_T * executableHandle, int childArgc, char** childArgv, char** envp)
{
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
      printSyscallInfoElf64(executableHandle);


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
      err = launchSyscallTraceElf64((ELF64_EXECUTABLE_HANDLE_T *) executableHandle, childArgc, childArgs, envp);
      break;
    
    case ELFCLASS32:
      break;

    case ELFCLASSNONE:
    default:
      return ERR_INVALID_ARGUMENT;
  }

  
  
  return ERR_NONE;
}

