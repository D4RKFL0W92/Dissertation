/*
 * Copywrite: 2023 Calum Dawson calumjamesdawson@gmail.com
*/

#include "elfdynamic.h"

static void printMsyncFlags(int flags)
{
  if((flags & MS_ASYNC) == MS_ASYNC)
  {
    printf(" MS_ASYNC )\n");
  }
  else if((flags & MS_SYNC) == MS_SYNC)
  {
    printf(" MS_SYNC )\n");
  }

  if(((flags & MS_INVALIDATE) == MS_INVALIDATE))
  {
    printf(" MS_INVALIDATE ");
  }
}
/* String values related to mmap flags. */
const char MAP_SHARED_STR[]     = " MAP_SHARED ";
const char MAP_PRIVATE_STR[]    = " MAP_PRIVATE ";
const char MAP_ANONYMOUS_STR[]  = " MAP_ANONYMOUS ";

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif
static uint8_t printMmapFlags(int flags)
{
  char flagBuff[ sizeof(MAP_SHARED_STR) +
                 sizeof(MAP_PRIVATE_STR) +
                 sizeof(MAP_ANONYMOUS_STR) + 1 ] = {0};
  // Allow for newline and spaces between flags.
  uint8_t flagsSet = 0;

  if( (flags & MAP_SHARED) == MAP_SHARED)
  {
    strcpy(flagBuff, MAP_SHARED_STR);
    flagsSet += 1;
  }
  if( (flags & MAP_PRIVATE) == MAP_PRIVATE)
  {
    strcat(flagBuff, MAP_PRIVATE_STR);
    flagsSet += 1;
  }
  if( (flags & MAP_ANONYMOUS) == MAP_ANONYMOUS)
  {
    strcat(flagBuff, MAP_PRIVATE_STR);
    flagsSet += 1;
  }
  printf("%s", flagBuff);

  return flagsSet;
}

int8_t readStringFromProcessMemory(pid_t pid, uint64_t offset, char** pStr)
{
  uint16_t allocationSize = 40;
  char *   data       = NULL;
  char *   pChar      = NULL;
  int8_t   err        = ERR_NONE;
  long     wordRead   = 0;
  BOOL     nullRead   = FALSE;
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
    wordRead = ptrace(PTRACE_PEEKDATA, pid, offset + charCount, NULL);
    pChar = (char *)& wordRead;
    for(uint8_t i = 0; i < sizeof(long); i++)
    {
      if(*pChar == '\0')
      {
        cpySize = i;
        nullRead = TRUE;
        break;
      }
      else if(*pChar <= 0x20 || *pChar >= 0x7E) // Outside the ASCII range
      {
        cpySize = i;
        nullRead = TRUE;
        break;
      }
      else
      {
        cpySize = sizeof(long);
      }
      pChar++;
    }

    memcpy(data + charCount, &wordRead, cpySize);

    charCount += sizeof(long);
    // TODO: Is the reallocation code correct??
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

int8_t readProcessMemoryFromPID(pid_t pid, const void * srcAddr, void * dstAddr, uint64_t uCount)
{
  uint16_t iterations = 0;
  long     wordRead   = 0;

  // Is this calculation correct when we read a partial word of memory.
  iterations = (uCount % sizeof(long) == 0) ? uCount / sizeof(long) : uCount / sizeof(long) + 1;
  if(iterations == 0)
  {
    return ERR_INVALID_ARGUMENT;
  }

  memset(dstAddr, 0, uCount);

  for(uint16_t i = 0; i < iterations; i++)
  {
    wordRead = 0;
    wordRead = ptrace(PTRACE_PEEKDATA, pid, (long *)(srcAddr + i * sizeof(long)), NULL);
    memcpy(dstAddr + i * sizeof(long), &wordRead, sizeof(long));
  }

  return ERR_NONE;
}

static int8_t printSyscallInfoElf64(ELF64_EXECUTABLE_HANDLE_T * executableHandle, BOOL firstSysCall)
{
  char* tmpBuffer = NULL;
  int8_t err = ERR_NONE;

  switch(executableHandle->regs.orig_rax)
  {
    case SYS_read:
      tmpBuffer = malloc(executableHandle->regs.rdx);
      if(tmpBuffer == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }
      err = readProcessMemoryFromPID(executableHandle->pid,
                                           executableHandle->regs.rsi,
                                           tmpBuffer,
                                           executableHandle->regs.rdx);

      printf("read(fd=%d, buffer=\"%s\", count=%d)\n",
        executableHandle->regs.rdi,
        tmpBuffer,
        executableHandle->regs.rdx);
      break; /*SYS_read*/

    case SYS_write:
      if(executableHandle->regs.rdx > 0)
      {
        tmpBuffer = malloc(executableHandle->regs.rdx);
        if(tmpBuffer == NULL)
        {
          return ERR_MEMORY_ALLOCATION_FAILED;
        }
        err = readProcessMemoryFromPID(executableHandle->pid,
                                       executableHandle->regs.rsi,
                                       tmpBuffer,
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
      err = readStringFromProcessMemory(executableHandle->pid, executableHandle->regs.rdi, &tmpBuffer);
      printf("open(path=%s)\n", tmpBuffer);
      break; /*SYS_open*/

    case SYS_close:
      printf("close(fd=%d)\n", executableHandle->regs.rdi);
      break; /*SYS_close*/

    case SYS_stat:
    case SYS_lstat:
      err = readStringFromProcessMemory(executableHandle->pid, executableHandle->regs.rdi, &tmpBuffer);

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
      printf("mmap(address=0x%08x, length=0x%08x, protections=0x%08x, flags=0x%08x, " \
        "fd=%d, offset=0x%08x)\n",
            executableHandle->regs.rdi,
            executableHandle->regs.rsi,
            executableHandle->regs.rdx,
            executableHandle->regs.r10,
            executableHandle->regs.r8,
            executableHandle->regs.r9);
      printf("Flags: ");
      printMmapFlags(executableHandle->regs.r10);
      printf("\n");
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
      /*
       * TODO: Is it worth printing the bytes that are being read?
       * YES, error handling for if tmpBuffer is null should be added
      */
      tmpBuffer = malloc(executableHandle->regs.rdx);
      if(tmpBuffer == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }
      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.rsi,
                                     tmpBuffer,
                                     executableHandle->regs.rdx);
      printf("pread64(fd=%d, buff=%p, count=0x%08x, position=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10);
      break; /*SYS_pread64*/

    case SYS_pwrite64:
      tmpBuffer = malloc(executableHandle->regs.rdx);
      if(tmpBuffer == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }
      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.rsi,
                                     tmpBuffer,
                                     executableHandle->regs.rdx);
      printf("pwrite64(fd=%d, buff=%p, count=0x%08x, position=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10);
      break; /*SYS_pwrite64*/

    case SYS_readv:
      tmpBuffer = malloc(executableHandle->regs.rdx);
      if(tmpBuffer == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }
      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.rsi,
                                     tmpBuffer,
                                     executableHandle->regs.rdx);
      printf("readv(fd=%d, iovec=%p, vec-len=0x%08x)\n", // TODO: Check if it's even possible to read iovec?
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_readv*/

    case SYS_writev:
      tmpBuffer = malloc(executableHandle->regs.rdx);
      if(tmpBuffer == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }
      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.rsi,
                                     tmpBuffer,
                                     executableHandle->regs.rdx);
      printf("writev(fd=%d, iovec=%p, vec-len=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_writev*/

    case SYS_access:
      err = readStringFromProcessMemory(executableHandle->pid, executableHandle->regs.rdi, &tmpBuffer);
      printf("access(filename=\"%s\", mode=0x%08x)\n",
        tmpBuffer,
        executableHandle->regs.rsi);
      break; /*SYS_access*/

    case SYS_pipe:
      printf("pipe(fd=%d)\n",
        executableHandle->regs.rdi);
      break; /*SYS_pipe*/

    case SYS_select:
      printf("select(n=%d, inp=%p, outp=%p, exp=%p, timeval=%ld)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10,
        executableHandle->regs.r8);
      break; /*SYS_select*/

    case SYS_sched_yield:
      printf("sched_yield()\n");
      break; /*SYS_sched_yield*/

    case SYS_mremap:
      printf("mremap(oldaddr=%p, oldlength=0x%08x, newlength=0x%08x, flags=0x%08x, newaddr=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10,
        executableHandle->regs.r8);
      printMmapFlags(executableHandle->regs.r10);
      break; /*SYS_mremap*/

    case SYS_msync:
      printf("msync(start=%ld, size=0x%08x, flags=",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);
      printMsyncFlags(executableHandle->regs.rdx);
      break; /*SYS_msync*/

    case SYS_mincore:
      printf("mincore(addr=%p, size=0x%08x, vec=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_mincore*/

    case SYS_madvise:
    /*TODO: Print the bahaviour arguments.*/
      printf("madvise(start=%p, length=0x%08x, behaviour=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_madvise*/

    case SYS_shmget:
      printf("shmget(key=0x%08x, size=0x%08x, flag=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_shmget*/

    case SYS_shmat:
      printf("shmat(id=0x%08x, shmaddr=%p, flag=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_shmat*/

    case SYS_shmctl:
      printf("shmctl(id=0x%08x, cmd=0x%08x, buff=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_shmctl*/

    case SYS_dup:
      printf("dup(fd=%d)\n", executableHandle->regs.rdi);
      break; /*SYS_dup*/

    case SYS_dup2:
      printf("dup2(id=%d, cmd=%d)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);
      break; /*SYS_dup2*/

    case SYS_pause:
      printf("pause()\n");
      break; /*SYS_pause*/

    case SYS_nanosleep:
      printf("nanosleep()\n");
      break; /*SYS_nanosleep*/

    /*
     * TODO: Write code to read itimer value from struct. This
     * is relavent for most timer related syscalls.
    */
    case SYS_getitimer:
      printf("getitimer(which=%d, valueAddr=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);
      break; /*SYS_getitimer*/

    case SYS_alarm:
      printf("alarm(seconds=%d)\n",
        executableHandle->regs.rdi);
      break; /*SYS_alarm*/

    case SYS_setitimer:
      printf("getitimer(which=%d, valueAddr=%p, ovalueAddr=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_setitimer*/

    case SYS_getpid:
      printf("getpid()\n"); // PID will be printed in return value by hiogher level function.
      break; /*SYS_getpid*/

    case SYS_sendfile:
      printf("sendfile(out_fd=%d, in_fd=%d, offset=%p, count=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10);
      break; /*SYS_sendfile*/

    case SYS_socket:
      printf("sendfile(domain=%d, type=%d, protocol=%d)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_socket*/

    case SYS_connect:
      printf("connect(sock_fd=%d, addr=%p, protocol=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_connect*/

    case SYS_accept:
      printf("accept(sock_fd=%d, addr=%p, protocol=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_accept*/

    case SYS_sendto:
      tmpBuffer = malloc(executableHandle->regs.rdx);
      if(tmpBuffer == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }
      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.rsi,
                                     tmpBuffer,
                                     executableHandle->regs.rdx);
      printf("sendto(fd=%d, buffAddr=%p, length=0x%08x, flags=0x%08x, dstAddr=0x%08x, addrLen=0x%08x)\n",
        executableHandle->regs.rdi,
        tmpBuffer,
        executableHandle->regs.rdx,
        executableHandle->regs.r10,
        executableHandle->regs.r8,
        executableHandle->regs.r9);
      break; /*SYS_sendto*/

    case SYS_recvfrom:
      /*
       * TODO: If we catch this on the syscall exit we could read the data.
      */
      printf("recvfrom(sock_fd=%d, buffAddr=%p, length=0x%08x, flags=0x%08x, srcAddr=0x%08x, addrLen=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10,
        executableHandle->regs.r8,
        executableHandle->regs.r9);
      break; /*SYS_recvfrom*/

    case SYS_sendmsg:
      printf("sendmsg(sock_fd=%d, buffAddr=%p, flags=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_sendmsg*/

    case SYS_recvmsg:
      printf("recvmsg(sock_fd=%d, buffAddr=%p, flags=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_recvmsg*/

    case SYS_shutdown:
      printf("shutdown(sock_fd=%d, how=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);
      break; /*SYS_shutdown*/

    case SYS_bind:
      printf("bind(sock_fd=%d, addr=%p, addrLen=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_bind*/

    case SYS_listen:
      printf("listen(sock_fd=%d, backlog=%d)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);
      break; /*SYS_listen*/

    case SYS_getsockname:
      printf("getsockname(sock_fd=%d, addr=%p, addrLen=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_getsockname*/

    case SYS_getpeername:
      printf("getpeername(sock_fd=%d, addr=%p, addrLen=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_getpeername*/

    case SYS_socketpair:
      printf("socketpair(domain=%d, type=%d, protocol=%d, sv=%d)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10);
      break; /*SYS_socketpair*/

    case SYS_setsockopt:
      printf("setsockopt(fd=%d, level=%d, optname=%d, optval=%p, optlen=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10,
        executableHandle->regs.r8);
      break; /*SYS_setsockopt*/

    case SYS_getsockopt:
      printf("getsockopt(fd=%d, level=%d, optname=%d, optval=%p, optlen=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10,
        executableHandle->regs.r8);
      break; /*SYS_getsockopt*/

    case SYS_clone:
      printf("clone(funcPtr=%p, stack=%p, flags=0x%08x, arg=%p, parent_tid=%d)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10,
        executableHandle->regs.r8);
      break; /*SYS_clone*/

    case SYS_fork:
      printf("fork()\n");
      break; /*SYS_fork*/

    case SYS_vfork:
      printf("vfork()\n");
      break; /*SYS_vfork*/

    case SYS_execve:
      if(firstSysCall)
      {
        break; // We have already printed execve syscall data in launchSyscallTraceElf64.
        // TODO: Could this be handled more optimally??
      }
      /*
       * TODO: Add error checking/handling
      */
      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer);
      // All registers except ORIG_RAX are zero. How can
      // we extract all arguments??? (This may noty be an issue
      // with later calls to execve).
      printf("execve()\n");
      break; /*SYS_execve*/

    case SYS_exit:
      printf("exit(errcode=%d)\n",
        executableHandle->regs.rdi);
      break; /*SYS_exit*/

    case SYS_wait4:
      printf("clone(pid=%d, status=%p, options=0x%08x, rusage=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10);
      break; /*SYS_clone*/

  }

  free(tmpBuffer);
  return err;
}

static uint8_t isRepeatedSyscallX64(REGS * regs1, REGS * regs2)
{
  if(regs1 == NULL || regs2 == NULL)
  {
    return FALSE;
  }
  if(regs1->orig_rax != regs2->orig_rax ||
     regs1->rdi != regs2->rdi ||
     regs1->rsi != regs2->rsi ||
     regs1->rdx != regs2->rdx ||
     regs1->r10 != regs2->r10 ||
     regs1->r8 != regs2->r8 ||
     regs1->r9 != regs2->r9)
  {
    return FALSE;
  }
  return TRUE;
}

static int8_t launchSyscallTraceElf64(ELF64_EXECUTABLE_HANDLE_T * executableHandle, int childArgc, char** childArgv, char** envp)
{
  static REGS oldRegisters = {0};
  struct ptrace_syscall_info syscallInfo = {0};
  BOOL firstSysCall  = TRUE;
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
    execve(executableHandle->fileHandle.path, childArgv, NULL);
    return ERR_NONE;
  }

  /*
   * Print the first syscall execve() and it's arguments.
  */
  printf("execve(\"%s\"", executableHandle->fileHandle.path);
  for(int i = 0; i < childArgc && childArgv[i] != NULL; i++)
  {
    printf(", \"%s\"", childArgv[i]);
  }
  printf(")\n\n");

  do
  {

    wait(&status);
    if(WIFEXITED(status))
    {
      executableHandle->isExecuting = FALSE;
    }
    else
    {
      // if (ptrace(PTRACE_GET_SYSCALL_INFO, executableHandle->pid,
			//            sizeof(struct ptrace_syscall_info), &syscallInfo) < 0)
      // {
      //   return ERR_PROCESS_OPERATION_FAILED;
      // }
      /* Get the syscall RAX value. */
      if(ptrace(PTRACE_GETREGS, executableHandle->pid,
                NULL, &executableHandle->regs) < 0)
      {
        return ERR_PROCESS_OPERATION_FAILED;
      }

      if(isRepeatedSyscallX64(&executableHandle->regs, &oldRegisters) == FALSE)
      {
        printf("Entering sycall number: %ld\n", executableHandle->regs.orig_rax);
        printSyscallInfoElf64(executableHandle, firstSysCall);
        firstSysCall = FALSE;
      }            
      else
      {
        // Get return code.
        printf("Returned With: %d\n\n", executableHandle->regs.rax);
      }

      /* Continue to the next syscall. */        
      ptrace(PTRACE_SYSCALL, executableHandle->pid, NULL, NULL);
      oldRegisters = executableHandle->regs;
    }

  } while(executableHandle->isExecuting);

  return ERR_NONE;
}

int8_t launchTraceProgram(ELF_EXECUTABLE_T * executableHandle, int childArgc, char** childArgs, char** envp)
{
  int8_t err = ERR_NONE;

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

  return err;
}

int8_t mapELF32ToHandleFromProcessMemory(void ** pMem, ELF32_EXECUTABLE_HANDLE_T ** elfHandle)
{
  enum BITS arch = T_NO_ELF;
  int8_t err     = ERR_NONE;

  if(pMem == NULL || (*pMem) == NULL)
  {
    #ifdef DEBUG
    perror("ERROR null parameter passed to mapELF32ToHandleFromProcessMemory()");
    #endif
    return ERR_NULL_ARGUMENT;
  }

  (*elfHandle) = malloc(sizeof(ELF32_EXECUTABLE_HANDLE_T));
  if((*elfHandle) == NULL)
  {
    #ifdef DEBUG
    perror("ERROR allocating memory in mapELF32ToHandleFromProcessMemory()");
    #endif
    return ERR_MEMORY_ALLOCATION_FAILED;
  }
  
  // Set all fields to zero as we want to set them here.
  memset((*elfHandle), 0, sizeof(ELF32_EXECUTABLE_HANDLE_T));

  (*elfHandle)->fileHandle.p_data = (*elfHandle)->fileHandle.p_data_seekPtr = (*pMem);
  (*elfHandle)->isExecuting       = TRUE;
  
  memcpy(&(*elfHandle)->ehdr, &(*pMem), sizeof(Elf32_Ehdr));
  (*elfHandle)->phdr = (*elfHandle)->ehdr->e_phoff;

  if((*elfHandle)->ehdr->e_shoff == 0 ||
     (*elfHandle)->ehdr->e_shnum == 0 ||
     (*elfHandle)->ehdr->e_shentsize == 0)
  {
    err = ERR_ELF_BINARY_STRIPPED;
  }

  (*elfHandle)->shdr = (*elfHandle)->ehdr->e_shoff;

  return ERR_NONE;
}

int8_t mapELF64ToHandleFromProcessMemory(void ** pMem, ELF64_EXECUTABLE_HANDLE_T ** elfHandle)
{
  enum BITS arch = T_NO_ELF;
  int8_t err     = ERR_NONE;

  if(pMem == NULL || (*pMem) == NULL)
  {
    #ifdef DEBUG
    perror("ERROR null parameter passed to mapELF64ToHandleFromProcessMemory()");
    #endif
    return ERR_NULL_ARGUMENT;
  }

  (*elfHandle) = malloc(sizeof(ELF64_EXECUTABLE_HANDLE_T));
  if((*elfHandle) == NULL)
  {
    #ifdef DEBUG
    perror("ERROR allocating memory in mapELF64ToHandleFromProcessMemory()");
    #endif
    return ERR_MEMORY_ALLOCATION_FAILED;
  }
  
  // Set all fields to zero as we want to set them here.
  memset((*elfHandle), 0, sizeof(ELF64_EXECUTABLE_HANDLE_T));

  (*elfHandle)->fileHandle.p_data = (*elfHandle)->fileHandle.p_data_seekPtr = (*pMem);
  (*elfHandle)->isExecuting       = TRUE;
  
  memcpy(&(*elfHandle)->ehdr, &(*pMem), sizeof(Elf64_Ehdr));
  (*elfHandle)->phdr = (*elfHandle)->ehdr->e_phoff;
  
  if((*elfHandle)->ehdr->e_shoff == 0 ||
     (*elfHandle)->ehdr->e_shnum == 0 ||
     (*elfHandle)->ehdr->e_shentsize == 0)
  {
    err = ERR_ELF_BINARY_STRIPPED;
  }
  
  (*elfHandle)->shdr = (*elfHandle)->ehdr->e_shoff;

  return ERR_NONE;
}

#ifdef UNITTEST

static void unittest_printMmapFlags()
{
  assert(printMmapFlags(MAP_SHARED | MAP_PRIVATE | MAP_ANONYMOUS) == 3);
  assert(printMmapFlags(MAP_SHARED | MAP_ANONYMOUS) == 2);
  assert(printMmapFlags(MAP_ANONYMOUS) == 1);
}

static void unittest_isRepeatedSyscallX64_legalUsage()
{
  REGS r1 = {0};
  REGS r2 = {0};
  uint8_t isRepeated = FALSE;

  isRepeated = isRepeatedSyscallX64(&r1, &r2);
  assert(isRepeated == TRUE);

  r1.r10 = 1;
  isRepeated = isRepeatedSyscallX64(&r1, &r2);
  assert(isRepeated == FALSE);

  r1.r10 = 0;
  r1.r9  = 1;
  isRepeated = isRepeatedSyscallX64(&r1, &r2);
  assert(isRepeated == FALSE);

  r1.r10 = 10;
  r1.r9  = 5;
  isRepeated = isRepeatedSyscallX64(&r1, &r2);
  assert(isRepeated == FALSE);

  r1.r10 = 20;
  r2.r10 = 20;
  r1.r9  = 0;
  isRepeated = isRepeatedSyscallX64(&r1, &r2);
  assert(isRepeated == TRUE);

  r1.r10 = 0;
  r2.r10 = 0;
  r1.rax = 10;
  r2.rax = 10;
  isRepeated = isRepeatedSyscallX64(&r1, &r2);
  assert(isRepeated == TRUE);
}



void unittest_mapELF32ToHandleFromProcessMemory_legalEhdr()
{
  /*
   * Typical Elf32_Ehdr
  */
  char buff[] =
  {
    0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x70, 0x10, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    0xe0, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x20, 0x00, 0x0b, 0x00, 0x28, 0x00,
    0x1e, 0x00, 0x1d, 0x00, 0x06, 0x40
  };

  ELF32_EXECUTABLE_HANDLE_T * handle  = NULL;
  char * pData = buff;
  int8_t err   = ERR_NONE;

  err = mapELF32ToHandleFromProcessMemory(&pData, &handle);
  assert(err == ERR_NONE);
  assert(handle->ehdr->e_type = ET_EXEC);
  assert(handle->ehdr->e_machine = EM_386);
  assert(handle->ehdr->e_version = EV_CURRENT);
  assert(handle->ehdr->e_entry == 0x1070);
  assert(handle->ehdr->e_phoff == 0x34);
  assert(handle->ehdr->e_shoff == 0x35e0);
  assert(handle->ehdr->e_phentsize == 0x20); // This seems wrong, TODO: Check this.
  assert(handle->ehdr->e_phnum == 0x0B);
  assert(handle->ehdr->e_shentsize == 0x28);
  assert(handle->ehdr->e_shnum == 0x1e);
  assert(handle->ehdr->e_shstrndx == 0x1d); // This seems wrong, TODO: Check this.
  assert(handle->isExecuting == TRUE);
  assert(handle->phdr == 0x34);
  assert(handle->shdr == 0x35e0);
  assert(handle->fileHandle.p_data == handle->fileHandle.p_data_seekPtr);

  free(handle);
}

void unittest_mapELF32ToHandleFromProcessMemory_nullMemoryPtr()
{
  char * ptr = NULL;
  ELF32_EXECUTABLE_HANDLE_T * handle  = NULL;
  int8_t err   = ERR_NONE;

  err = mapELF32ToHandleFromProcessMemory(&ptr, &handle);
  assert(err == ERR_NULL_ARGUMENT);
  assert(handle == NULL);

  err = mapELF32ToHandleFromProcessMemory(NULL, &handle);
  assert(err == ERR_NULL_ARGUMENT);
  assert(handle == NULL);
}

void unittest_mapELF64ToHandleFromProcessMemory_legalEhdr()
{
  /*
   * Typical Elf64_Ehdr
  */
  char buff[] =
  {
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x90, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x3d, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x0d, 0x00, 0x40, 0x00, 0x25, 0x00, 0x24, 0x00
  };

  ELF64_EXECUTABLE_HANDLE_T * handle  = NULL;
  char * pData = buff;
  int8_t err   = ERR_NONE;

  err = mapELF64ToHandleFromProcessMemory(&pData, &handle);
  assert(err == ERR_NONE);
  assert(handle->ehdr->e_type = ET_EXEC);
  assert(handle->ehdr->e_machine = EM_X86_64);
  assert(handle->ehdr->e_version = EV_CURRENT);
  assert(handle->ehdr->e_entry == 0x1290);
  assert(handle->ehdr->e_phoff == 0x40);
  assert(handle->ehdr->e_shoff == 0x23d88);
  assert(handle->ehdr->e_phentsize == 0x38);
  assert(handle->ehdr->e_phnum == 13);
  assert(handle->ehdr->e_shentsize == 0x40);
  assert(handle->ehdr->e_shnum == 37);
  assert(handle->ehdr->e_shstrndx == 36);
  assert(handle->isExecuting == TRUE);
  assert(handle->phdr == 0x40);
  assert(handle->shdr == 0x23D88);
  assert(handle->fileHandle.p_data == handle->fileHandle.p_data_seekPtr);

  free(handle);
}

void unittest_mapELF64ToHandleFromProcessMemory_legalEhdr_differentValues()
{
  /*
   * Typical Elf64_Ehdr
  */
  char buff[] =
  {
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0xfa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x99, 0x99, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x5F, 0x00, 0x0d, 0x00, 0x40, 0x00, 0x27, 0x00, 0x10, 0x00
  };

  ELF64_EXECUTABLE_HANDLE_T * handle  = NULL;
  char * pData = buff;
  int8_t err   = ERR_NONE;

  err = mapELF64ToHandleFromProcessMemory(&pData, &handle);
  assert(err == ERR_NONE);
  assert(handle->ehdr->e_type = ET_EXEC);
  assert(handle->ehdr->e_machine = EM_X86_64);
  assert(handle->ehdr->e_version = EV_CURRENT);
  assert(handle->ehdr->e_entry == 0xFA78);
  assert(handle->ehdr->e_phoff == 0x80);
  assert(handle->ehdr->e_shoff == 0x99999);
  assert(handle->ehdr->e_phentsize == 0x5F);
  assert(handle->ehdr->e_phnum == 13);
  assert(handle->ehdr->e_shentsize == 0x40);
  assert(handle->ehdr->e_shnum == 39);
  assert(handle->ehdr->e_shstrndx == 16);
  assert(handle->isExecuting == TRUE);
  assert(handle->phdr == 0x80);
  assert(handle->shdr == 0x99999);
  assert(handle->fileHandle.p_data == handle->fileHandle.p_data_seekPtr);

  free(handle);
}

void unittest_mapELF64ToHandleFromProcessMemory_illegalEhdr()
{
  /*
   * Typical Elf64_Ehdr
  */
  char buff[] =
  {
    0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  ELF64_EXECUTABLE_HANDLE_T * handle  = NULL;
  char * pData = buff;
  int8_t err   = ERR_NONE;

  err = mapELF64ToHandleFromProcessMemory(&pData, &handle);
  assert(err == ERR_INVALID_ARGUMENT);
  assert(handle == NULL);
}

void unittest_mapELF64ToHandleFromProcessMemory_nullMemoryPtr()
{
  char * ptr = NULL;
  ELF64_EXECUTABLE_HANDLE_T * handle  = NULL;
  int8_t err   = ERR_NONE;

  err = mapELF64ToHandleFromProcessMemory(&ptr, &handle);
  assert(err == ERR_NULL_ARGUMENT);
  assert(handle == NULL);

  err = mapELF64ToHandleFromProcessMemory(NULL, &handle);
  assert(err == ERR_NULL_ARGUMENT);
  assert(handle == NULL);
}

void elfDynamicTestSuite()
{
  unittest_printMmapFlags();
  unittest_isRepeatedSyscallX64_legalUsage();

  unittest_mapELF32ToHandleFromProcessMemory_legalEhdr();
  unittest_mapELF32ToHandleFromProcessMemory_nullMemoryPtr();

  unittest_mapELF64ToHandleFromProcessMemory_legalEhdr();
  unittest_mapELF64ToHandleFromProcessMemory_legalEhdr_differentValues();
  unittest_mapELF64ToHandleFromProcessMemory_nullMemoryPtr();
}
#endif /* UNITTEST */