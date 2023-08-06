/*
 * Copyright (c) [2023], Calum Dawson
 * All rights reserved.
 * This code is the exclusive property of Calum Dawson.
 * Any unauthorized use or reproduction without the explicit
 * permission of Calum Dawson is strictly prohibited.
 * Unauthorized copying of this file, via any medium, is
 * strictly prohibited.
 * Proprietary and confidential.
 * Written by Calum Dawson calumjamesdawson@gmail.com, [2023].
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
    #ifdef DEBUG
    perror("ERROR Allocating Memory In readStringFromProcessMemory()\n");
    #endif
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
  char * tmpBuffer1 = NULL;
  char * tmpBuffer2 = NULL;
  char * tmpBuffer3 = NULL;
  int8_t err = ERR_NONE;

  switch(executableHandle->regs.orig_rax)
  {
/***********************************************************************************/ 
    case SYS_read:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      
      tmpBuffer1 = malloc(executableHandle->regs.rdx);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }
      err = readProcessMemoryFromPID(executableHandle->pid,
                                           executableHandle->regs.rsi,
                                           tmpBuffer1,
                                           executableHandle->regs.rdx);

      if(isAsciidata(tmpBuffer1, executableHandle->regs.rdx) == TRUE)
      {
        printf("read(fd=%d, buffer=\"%s\", count=%d)\n",
                     executableHandle->regs.rdi,
                     tmpBuffer1,
                     executableHandle->regs.rdx);
      }
      else
      {
        // TODO: Write a function to print hex bytes as a string
        printf("read(fd=%d, buffer-addr=%p, count=%d)\n",
                     executableHandle->regs.rdi,
                     executableHandle->regs.rdx,
                     executableHandle->regs.rdx);
      }


      // TODO: Can we check that the read bytes is initialised data before dumping the bytes.
      // dumpHexBytesFromOffset(tmpBuffer1, 0, executableHandle->regs.rdx);
      break; /*SYS_read*/

/***********************************************************************************/ 
    case SYS_write:
      if(executableHandle->regs.rdx > 0)
      {
        tmpBuffer1 = malloc(executableHandle->regs.rdx);
        if(tmpBuffer1 == NULL)
        {
          return ERR_MEMORY_ALLOCATION_FAILED;
        }
        err = readProcessMemoryFromPID(executableHandle->pid,
                                       executableHandle->regs.rsi,
                                       tmpBuffer1,
                                       executableHandle->regs.rdx);

        tmpBuffer1 = realloc(tmpBuffer1, executableHandle->regs.rdx + 1);
        tmpBuffer1[executableHandle->regs.rdx] = '\0'; // Remove extra \n that may be output by command.
      }
      printf("write(fd=%d, buffer=\"%s\", count=%d)\n",
        executableHandle->regs.rdi,
        tmpBuffer1,
        executableHandle->regs.rdx);
      break; /*SYS_write*/

/***********************************************************************************/ 
    case SYS_open:
      err = readStringFromProcessMemory(executableHandle->pid, executableHandle->regs.rdi, &tmpBuffer1);
      printf("open(path=%s)\n", tmpBuffer1);
      break; /*SYS_open*/

/***********************************************************************************/ 
    case SYS_close:
      printf("close(fd=%d)\n", executableHandle->regs.rdi);
      break; /*SYS_close*/

/***********************************************************************************/ 
    case SYS_stat:
/***********************************************************************************/ 
    case SYS_lstat:
      err = readStringFromProcessMemory(executableHandle->pid, executableHandle->regs.rdi, &tmpBuffer1);

      printf("stat(path=\"%s\", struct=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);
      break; /*stat/lstat*/

/***********************************************************************************/ 
    case SYS_fstat:
      printf("fstat(fd=%d, struct=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);
      break;

/***********************************************************************************/ 
    case SYS_poll:
      printf("poll(pollfd=%p, nfds=%d, timeout=%d)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_poll*/

/***********************************************************************************/ 
    case SYS_lseek:
      printf("lseek(fd=%d, offset=%p, whence=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_lseek*/

/***********************************************************************************/ 
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

/***********************************************************************************/ 
    case SYS_mprotect:
      printf("mprotect(start=%p, size=0x%08x, protections=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_mprotect*/

/***********************************************************************************/ 
    case SYS_munmap:
      printf("munmap(address=%p, size=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);
      break; /*SYS_munmap*/

/***********************************************************************************/ 
    case SYS_brk:
      printf("brk(brk=0x%08x)\n", executableHandle->regs.rdi);
      break; /*SYS_brk*/

/***********************************************************************************/ 
    case SYS_rt_sigaction:
      printf("rt_sigaction(signum=%d, sig-new-action=0x%08x, " \
             "sig-old-action=0x%08x, size=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx,
              executableHandle->regs.r10);
      break; /*SYS_rt_sigaction*/

/***********************************************************************************/ 
    case SYS_rt_sigprocmask:
      printf("rt_sigprocmask(how=%d, sig-new-set=0x%08x, " \
            "sig-old-set=0x%08x, size=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx,
              executableHandle->regs.r10);
      break; /*SYS_rt_sigprocmask*/

/***********************************************************************************/ 
    case SYS_rt_sigreturn:
      printf("rt_sigreturn()\n");
      break; /*SYS_rt_sigreturn*/

/***********************************************************************************/ 
    case SYS_ioctl:
      printf("ioctl(fd=%d, cmd=%d, arg=%ld)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_ioctl*/

/***********************************************************************************/ 
    case SYS_pread64:
      /*
       * TODO: Is it worth printing the bytes that are being read?
       * YES
      */
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      tmpBuffer1 = malloc(executableHandle->regs.rdx);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }
      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.rsi,
                                     tmpBuffer1,
                                     executableHandle->regs.rdx);
      if(err != ERR_NONE)
      {
        return err;
      }

      if(isAsciidata(tmpBuffer1, executableHandle->regs.rdx))
      {
        printf("pread64(fd=%d, buff=\"%s\", count=0x%08x, position=%p)\n",
          executableHandle->regs.rdi,
          tmpBuffer1,
          executableHandle->regs.rdx,
          executableHandle->regs.r10);

      }
      else
      {
        printf("pread64(fd=%d, buff-add=%p, count=0x%08x, position=%p)\n",
          executableHandle->regs.rdi,
          executableHandle->regs.rsi,
          executableHandle->regs.rdx,
          executableHandle->regs.r10);
      }
      break; /*SYS_pread64*/

/***********************************************************************************/ 
    case SYS_pwrite64:
      tmpBuffer1 = malloc(executableHandle->regs.rdx);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }
      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.rsi,
                                     tmpBuffer1,
                                     executableHandle->regs.rdx);
      printf("pwrite64(fd=%d, buff=%p, count=0x%08x, position=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10);
      break; /*SYS_pwrite64*/

/***********************************************************************************/ 
    case SYS_readv:
      tmpBuffer1 = malloc(executableHandle->regs.rdx);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }
      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.rsi,
                                     tmpBuffer1,
                                     executableHandle->regs.rdx);
      printf("readv(fd=%d, iovec=%p, vec-len=0x%08x)\n", // TODO: Check if it's even possible to read iovec?
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_readv*/

/***********************************************************************************/ 
    case SYS_writev:
      tmpBuffer1 = malloc(executableHandle->regs.rdx);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }
      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.rsi,
                                     tmpBuffer1,
                                     executableHandle->regs.rdx);
      printf("writev(fd=%d, iovec=%p, vec-len=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_writev*/

/***********************************************************************************/ 
    case SYS_access:
      err = readStringFromProcessMemory(executableHandle->pid, executableHandle->regs.rdi, &tmpBuffer1);
      printf("access(filename=\"%s\", mode=0x%08x)\n",
        tmpBuffer1,
        executableHandle->regs.rsi);
      break; /*SYS_access*/

/***********************************************************************************/ 
    case SYS_pipe:
      printf("pipe(fd=%d)\n",
        executableHandle->regs.rdi);
      break; /*SYS_pipe*/

/***********************************************************************************/ 
    case SYS_select:
      printf("select(n=%d, inp=%p, outp=%p, exp=%p, timeval=%ld)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10,
        executableHandle->regs.r8);
      break; /*SYS_select*/

/***********************************************************************************/ 
    case SYS_sched_yield:
      printf("sched_yield()\n");
      break; /*SYS_sched_yield*/

/***********************************************************************************/ 
    case SYS_mremap:
      printf("mremap(oldaddr=%p, oldlength=0x%08x, newlength=0x%08x, flags=0x%08x, newaddr=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10,
        executableHandle->regs.r8);
      printMmapFlags(executableHandle->regs.r10);
      break; /*SYS_mremap*/

/***********************************************************************************/ 
    case SYS_msync:
      printf("msync(start=%ld, size=0x%08x, flags=",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);
      printMsyncFlags(executableHandle->regs.rdx);
      break; /*SYS_msync*/

/***********************************************************************************/ 
    case SYS_mincore:
      printf("mincore(addr=%p, size=0x%08x, vec=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_mincore*/

/***********************************************************************************/ 
    case SYS_madvise:
    /*TODO: Print the bahaviour arguments.*/
      printf("madvise(start=%p, length=0x%08x, behaviour=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_madvise*/

/***********************************************************************************/ 
    case SYS_shmget:
      printf("shmget(key=0x%08x, size=0x%08x, flag=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_shmget*/

/***********************************************************************************/ 
    case SYS_shmat:
      printf("shmat(id=0x%08x, shmaddr=%p, flag=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_shmat*/

/***********************************************************************************/ 
    case SYS_shmctl:
      printf("shmctl(id=0x%08x, cmd=0x%08x, buff=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_shmctl*/

/***********************************************************************************/ 
    case SYS_dup:
      printf("dup(fd=%d)\n", executableHandle->regs.rdi);
      break; /*SYS_dup*/

/***********************************************************************************/ 
    case SYS_dup2:
      printf("dup2(id=%d, cmd=%d)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);
      break; /*SYS_dup2*/

/***********************************************************************************/ 
    case SYS_pause:
      printf("pause()\n");
      break; /*SYS_pause*/

/***********************************************************************************/ 
    case SYS_nanosleep:
      printf("nanosleep()\n");
      break; /*SYS_nanosleep*/

    /*
     * TODO: Write code to read itimer value from struct. This
     * is relavent for most timer related syscalls.
    */
/***********************************************************************************/ 
    case SYS_getitimer:
      printf("getitimer(which=%d, valueAddr=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);
      break; /*SYS_getitimer*/

/***********************************************************************************/ 
    case SYS_alarm:
      printf("alarm(seconds=%d)\n",
        executableHandle->regs.rdi);
      break; /*SYS_alarm*/

/***********************************************************************************/ 
    case SYS_setitimer:
      printf("getitimer(which=%d, valueAddr=%p, ovalueAddr=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_setitimer*/

/***********************************************************************************/ 
    case SYS_getpid:
      printf("getpid()\n");
      break; /*SYS_getpid*/

/***********************************************************************************/ 
    case SYS_sendfile:
      printf("sendfile(out_fd=%d, in_fd=%d, offset=%p, count=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10);
      break; /*SYS_sendfile*/

/***********************************************************************************/ 
    case SYS_socket:
      printf("sendfile(domain=%d, type=%d, protocol=%d)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_socket*/

/***********************************************************************************/ 
    case SYS_connect:
      printf("connect(sock_fd=%d, addr=%p, protocol=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_connect*/

/***********************************************************************************/ 
    case SYS_accept:
      printf("accept(sock_fd=%d, addr=%p, protocol=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_accept*/

/***********************************************************************************/ 
    case SYS_sendto:
      tmpBuffer1 = malloc(executableHandle->regs.rdx);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }
      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.rsi,
                                     tmpBuffer1,
                                     executableHandle->regs.rdx);
      printf("sendto(fd=%d, buffAddr=%p, length=0x%08x, flags=0x%08x, dstAddr=0x%08x, addrLen=0x%08x)\n",
        executableHandle->regs.rdi,
        tmpBuffer1,
        executableHandle->regs.rdx,
        executableHandle->regs.r10,
        executableHandle->regs.r8,
        executableHandle->regs.r9);
      break; /*SYS_sendto*/

/***********************************************************************************/ 
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

/***********************************************************************************/ 
    case SYS_sendmsg:
      printf("sendmsg(sock_fd=%d, buffAddr=%p, flags=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_sendmsg*/

/***********************************************************************************/ 
    case SYS_recvmsg:
      printf("recvmsg(sock_fd=%d, buffAddr=%p, flags=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_recvmsg*/

/***********************************************************************************/ 
    case SYS_shutdown:
      printf("shutdown(sock_fd=%d, how=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);
      break; /*SYS_shutdown*/

/***********************************************************************************/ 
    case SYS_bind:
      printf("bind(sock_fd=%d, addr=%p, addrLen=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_bind*/

/***********************************************************************************/ 
    case SYS_listen:
      printf("listen(sock_fd=%d, backlog=%d)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);
      break; /*SYS_listen*/

/***********************************************************************************/ 
    case SYS_getsockname:
      printf("getsockname(sock_fd=%d, addr=%p, addrLen=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_getsockname*/

/***********************************************************************************/ 
    case SYS_getpeername:
      printf("getpeername(sock_fd=%d, addr=%p, addrLen=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_getpeername*/

/***********************************************************************************/ 
    case SYS_socketpair:
      printf("socketpair(domain=%d, type=%d, protocol=%d, sv=%d)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10);
      break; /*SYS_socketpair*/

/***********************************************************************************/ 
    case SYS_setsockopt:
      printf("setsockopt(fd=%d, level=%d, optname=%d, optval=%p, optlen=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10,
        executableHandle->regs.r8);
      break; /*SYS_setsockopt*/

/***********************************************************************************/ 
    case SYS_getsockopt:
      printf("getsockopt(fd=%d, level=%d, optname=%d, optval=%p, optlen=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10,
        executableHandle->regs.r8);
      break; /*SYS_getsockopt*/

/***********************************************************************************/ 
    case SYS_clone:
      printf("clone(funcPtr=%p, stack=%p, flags=0x%08x, arg=%p, parent_tid=%d)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10,
        executableHandle->regs.r8);
      break; /*SYS_clone*/

/***********************************************************************************/ 
    case SYS_fork:
      printf("fork()\n");
      break; /*SYS_fork*/

/***********************************************************************************/ 
    case SYS_vfork:
      printf("vfork()\n");
      break; /*SYS_vfork*/

/***********************************************************************************/ 
    case SYS_execve:
      if(firstSysCall)
      {
        break; // We have already printed execve syscall data in launchSyscallTraceElf64.
        // TODO: Could this be handled more optimally??
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      // All registers except ORIG_RAX are zero. How can
      // we extract all arguments??? (This may not be an issue
      // with later calls to execve).
      printf("execve()\n");
      break; /*SYS_execve*/

/***********************************************************************************/ 
    case SYS_exit:
      printf("exit(errcode=%d)\n",
        executableHandle->regs.rdi);
      break; /*SYS_exit*/

/***********************************************************************************/ 
    case SYS_wait4:
      printf("clone(pid=%d, status=%p, options=0x%08x, rusage=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10);
      break; /*SYS_clone*/

/***********************************************************************************/ 
    case SYS_kill:
      printf("kill(pid=%d, signal=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);
      break; /*SYS_kill*/

/***********************************************************************************/ 
    case SYS_uname:
      printf("uname(pid=%p)\n",
        executableHandle->regs.rdi);
      break; /*SYS_uname*/

/***********************************************************************************/ 
    case SYS_semget:
      printf("semget(key=%d, nsems=%d, semflags=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_semget*/

/***********************************************************************************/ 
    case SYS_semop:
      printf("semop(semid=%d, semops=%p, nsops=%d)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);
      break; /*SYS_semop*/

/***********************************************************************************/ 
    case SYS_semctl:
      printf("semctl(semid=%d, semnum=%d, cmd=0x%08x, arg=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10);
      break; /*SYS_semctl*/

/***********************************************************************************/ 
    case SYS_shmdt:
      printf("shmdt(shmaddr=%p)\n",
        executableHandle->regs.rdi);
      break; /*SYS_shmdt*/

/***********************************************************************************/ 
    case SYS_msgget:
      printf("msgget(key=%d, msgflags=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);
      break; /*SYS_msgget*/

/***********************************************************************************/ 
    case SYS_msgsnd:
      printf("msgsnd(msqid=%d, msgptr=%p, msgsize=0x%08x, msgflags=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx,
              executableHandle->regs.r10);
      break; /*SYS_msgsnd*/

/***********************************************************************************/ 
    case SYS_msgrcv:
      printf("msgrcv(msqid=%d, msgptr=%p, msgsize=0x%08x, msgtyp=%d, msgflags=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx,
              executableHandle->regs.r10,
              executableHandle->regs.r8);
      break; /*SYS_msgrcv*/

/***********************************************************************************/ 
    case SYS_msgctl:
      printf("msgctl(msqid=%d, cmd=0x%08x, msgptr=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);
      break; /*SYS_msgctl*/

/***********************************************************************************/ 
    case SYS_fcntl:
      printf("fcntl(fd=%d, cmd=0x%08x, buff=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);
      break; /*SYS_fcntl*/

/***********************************************************************************/ 
    case SYS_flock:
      printf("flock(fd=%d, cmd=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);
      break; /*SYS_flock*/

/***********************************************************************************/ 
    case SYS_fsync:
      printf("fsync(fd=%d)\n",
              executableHandle->regs.rdi);
      break; /*SYS_fsync*/

/***********************************************************************************/ 
    case SYS_fdatasync:
      printf("fdatasync(fd=%d)\n",
              executableHandle->regs.rdi);
      break; /*SYS_fdatasync*/

/***********************************************************************************/ 
    case SYS_truncate:
      err = readStringFromProcessMemory(executableHandle->pid,
                                        tmpBuffer1,
                                        &tmpBuffer1);

      printf("truncate(path=%s, size=0x%08x)\n",
              tmpBuffer1,
              executableHandle->regs.rsi);
      break; /*SYS_truncate*/

/***********************************************************************************/ 
    case SYS_ftruncate:
      printf("ftruncate(fd=%d, size=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);
      break; /*SYS_ftruncate*/

/***********************************************************************************/ 
    case SYS_getdents:
      /* TODO: Can we read the directory entries?? */
      printf("getdents(fd=%d, dirents=%p, nentries=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);
      break; /*SYS_getdents*/

/***********************************************************************************/ 
    case SYS_getcwd:
      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      printf("getcwd(buffer=%d, size=0x%08x)\n",
              tmpBuffer1,
              executableHandle->regs.rsi);
      break; /*SYS_getcwd*/

/***********************************************************************************/ 
    case SYS_chdir:
      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      printf("chdir(path=%d)\n", tmpBuffer1);
      break; /*SYS_chdir*/

/***********************************************************************************/ 
    case SYS_fchdir:
      printf("fchdir(fd=%d)\n", executableHandle->regs.rdi);
      break; /*SYS_fchdir*/

/***********************************************************************************/ 
    case SYS_rename:
      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rsi,
                                        &tmpBuffer2);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("rename(old-name=\"%s\", new-name=\"%s\")\n", tmpBuffer1, tmpBuffer2);
      break; /*SYS_rename*/

/***********************************************************************************/ 
    case SYS_mkdir:
      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);

      /* TODO: Print mode in human readable format.*/
      printf("mkdir(name=%d, mode=0x%08x)\n",
             tmpBuffer1,
             executableHandle->regs.rsi);
      break; /*SYS_mkdir*/

/***********************************************************************************/ 
    case SYS_rmdir:
      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);

      printf("rmdir(name=%d)\n", tmpBuffer1);
      break; /*SYS_rmdir*/

/***********************************************************************************/ 
    case SYS_creat:
      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
                                        
      /* TODO: Print mode in human readable format.*/
      printf("creat(name=%d, mode=0x%08x)\n",
             tmpBuffer1,
             executableHandle->regs.rsi);
      break; /*SYS_creat*/

/***********************************************************************************/ 
    case SYS_link:
      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rsi,
                                        &tmpBuffer2);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("link(old-name=\"%s\", new-name=\"%s\")\n", tmpBuffer1, tmpBuffer2);
      break; /*SYS_link*/

/***********************************************************************************/ 
    case SYS_unlink:
      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("unlink(pathname=\"%s\")\n", tmpBuffer1);
      break; /*SYS_unlink*/

/***********************************************************************************/ 
    case SYS_symlink:
      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rsi,
                                        &tmpBuffer2);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("symlink(old-name=\"%s\", new-name=\"%s\")\n", tmpBuffer1, tmpBuffer2);
      break; /*SYS_symlink*/

/***********************************************************************************/ 
    case SYS_readlink:
      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      /* Todo: We could progress to next syscall (syscall exit)
       * then read the resulting buffer (RSI)
       */

      printf("readlink(path=\"%s\", buff=%p, buffsize=0x%08x)\n",
             tmpBuffer1,
             tmpBuffer2,
             executableHandle->regs.rdx);
      break; /*SYS_readlink*/

/***********************************************************************************/ 
    case SYS_chmod:
      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("chmod(path=\"%s\", mode=0x%08x)\n",
             tmpBuffer1,
             executableHandle->regs.rsi);
      break; /*SYS_chmod*/

/***********************************************************************************/ 
    case SYS_fchmod:

      printf("fchmod(fd=%d, mode=0x%08x)\n",
             executableHandle->regs.rdi,
             executableHandle->regs.rsi);
      break; /*SYS_fchmod*/

/***********************************************************************************/ 
    case SYS_chown:
      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("chown(path=\"%s\", uid=0x%08x, gid=0x%08x)\n",
             tmpBuffer1,
             executableHandle->regs.rsi,
             executableHandle->regs.rdx);
      break; /*SYS_chown*/

/***********************************************************************************/ 
    case SYS_fchown:
      printf("fchown(fd=%d, uid=0x%08x, gid=0x%08x)\n",
             executableHandle->regs.rdi,
             executableHandle->regs.rsi,
             executableHandle->regs.rdx);
      break; /*SYS_fchown*/

/***********************************************************************************/ 
    case SYS_umask:
      printf("umask(mask=0x%08x)\n", executableHandle->regs.rdi);
      break; /*SYS_umask*/

/***********************************************************************************/ 
    case SYS_gettimeofday:
      printf("gettimeofday()\n"); // Not really much point printing the received data.
      break; /*SYS_gettimeofday*/

/***********************************************************************************/ 
    case SYS_getrlimit:
      printf("getrlimit(resource=0x%08x, rlimit=%p)\n",
             executableHandle->regs.rdi,
             executableHandle->regs.rsi);
      break; /*SYS_getrlimit*/

/***********************************************************************************/ 
    case SYS_getrusage:
      printf("getrusage(who=%d)\n", executableHandle->regs.rdi);
      break; /*SYS_getrusage*/

/***********************************************************************************/ 
    case SYS_sysinfo:
      printf("sysinfo()\n");
      break; /*SYS_sysinfo*/

/***********************************************************************************/ 
    case SYS_times:
      printf("times(tms-addr=%p)\n", executableHandle->regs.rdi);
      break; /*SYS_times*/

/***********************************************************************************/ 
    case SYS_ptrace:
    {
      switch(executableHandle->regs.rdi)
      {
        case PTRACE_GETREGS:
              printf("ptrace(request=PTRACE_GETREGS, pid=%d, addr=0x%016x, data=0x%016x)\n",
                    executableHandle->regs.rsi,
                    executableHandle->regs.rdx,
                    executableHandle->regs.r10);
              break;

        case PTRACE_SETREGS:
              printf("ptrace(request=PTRACE_SETREGS, pid=%d, addr=0x%016x, data=0x%016x)\n",
                    executableHandle->regs.rsi,
                    executableHandle->regs.rdx,
                    executableHandle->regs.r10);
              break;

        case PTRACE_GETFPREGS:
              printf("ptrace(request=PTRACE_GETFPREGS, pid=%d, addr=0x%016x, data=0x%016x)\n",
                    executableHandle->regs.rsi,
                    executableHandle->regs.rdx,
                    executableHandle->regs.r10);
              break;

        case PTRACE_SETFPREGS:
              printf("ptrace(request=PTRACE_SETFPREGS, pid=%d, addr=0x%016x, data=0x%016x)\n",
                    executableHandle->regs.rsi,
                    executableHandle->regs.rdx,
                    executableHandle->regs.r10);
              break;

        case PTRACE_GETFPXREGS:
              printf("ptrace(request=PTRACE_GETFPXREGS, pid=%d, addr=0x%016x, data=0x%016x)\n",
                    executableHandle->regs.rsi,
                    executableHandle->regs.rdx,
                    executableHandle->regs.r10);
              break;

        case PTRACE_SETFPXREGS:
              printf("ptrace(request=PTRACE_SETFPXREGS, pid=%d, addr=0x%016x, data=0x%016x)\n",
                    executableHandle->regs.rsi,
                    executableHandle->regs.rdx,
                    executableHandle->regs.r10);
              break;

        case PTRACE_OLDSETOPTIONS:
              printf("ptrace(request=PTRACE_OLDSETOPTIONS, pid=%d, addr=0x%016x, data=0x%016x)\n",
                    executableHandle->regs.rsi,
                    executableHandle->regs.rdx,
                    executableHandle->regs.r10);
              break;

        case PTRACE_GET_THREAD_AREA:
              printf("ptrace(request=PTRACE_GET_THREAD_AREA, pid=%d, addr=0x%016x, data=0x%016x)\n",
                    executableHandle->regs.rsi,
                    executableHandle->regs.rdx,
                    executableHandle->regs.r10);
              break;

        case PTRACE_SET_THREAD_AREA:
              printf("ptrace(request=PTRACE_SET_THREAD_AREA, pid=%d, addr=0x%016x, data=0x%016x)\n",
                    executableHandle->regs.rsi,
                    executableHandle->regs.rdx,
                    executableHandle->regs.r10);
              break;
    #ifdef __x86_64__
        case PTRACE_ARCH_PRCTL:
              printf("ptrace(request=PTRACE_ARCH_PRCTL, pid=%d, addr=0x%016x, data=0x%016x)\n",
                    executableHandle->regs.rdi,
                    executableHandle->regs.rsi,
                    executableHandle->regs.rdx,
                    executableHandle->regs.r10);
              break;
    #endif

        case PTRACE_SYSEMU:
              printf("ptrace(request=PTRACE_SYSEMU, pid=%d, addr=0x%016x, data=0x%016x)\n",
                    executableHandle->regs.rsi,
                    executableHandle->regs.rdx,
                    executableHandle->regs.r10);
              break;

        case PTRACE_SYSEMU_SINGLESTEP:
              printf("ptrace(request=PTRACE_SYSEMU_SINGLESTEP, pid=%d, addr=0x%016x, data=0x%016x)\n",
                    executableHandle->regs.rsi,
                    executableHandle->regs.rdx,
                    executableHandle->regs.r10);
              break;

        case PTRACE_SINGLEBLOCK:
              printf("ptrace(request=PTRACE_SINGLEBLOCK, pid=%d, addr=0x%016x, data=0x%016x)\n",
                    executableHandle->regs.rsi,
                    executableHandle->regs.rdx,
                    executableHandle->regs.r10);
              break;

        case PTRACE_TRACEME:
              printf("ptrace(request=PTRACE_TRACEME, pid=%d, addr=0x%016x, data=0x%016x)\n",
                    executableHandle->regs.rsi,
                    executableHandle->regs.rdx,
                    executableHandle->regs.r10);
              puts("Anit-Debugging Detected, Exiting Now.");
              exit(1);

            default:
              printf("ptrace(request=0x%008x, pid=%d, addr=0x%016x, data=0x%016x)\n",
                    executableHandle->regs.rdi,
                    executableHandle->regs.rsi,
                    executableHandle->regs.rdx,
                    executableHandle->regs.r10);
              break;

      }
      break; /*SYS_ptrace*/

    }

/***********************************************************************************/ 
    case SYS_getuid:
      printf("getuid()\n"); // Prints UID on return.
      break; /*SYS_getuid*/

/***********************************************************************************/ 
    case SYS_syslog:
      printf("syslog(type=%d, buff=%p, size=0x%08x)\n",
             executableHandle->regs.rdi,
             executableHandle->regs.rsi,
             executableHandle->regs.rdx);
      /*
       * TODO: We could get the contents of kernel buffer.
       * We would have to progress to the syscall exit.
       */
      break; /*SYS_syslog*/

/***********************************************************************************/ 
    case SYS_getgid:
      printf("getgid()\n"); // Prints GID on return.
      break; /*SYS_getgid*/

/***********************************************************************************/ 
    case SYS_setuid:
      printf("setuid(uid=%s)\n", executableHandle->regs.rdi);
      break; /*SYS_setuid*/

/***********************************************************************************/ 
    case SYS_geteuid:
      printf("geteuid()\n");
      break; /*SYS_geteuid*/

/***********************************************************************************/ 
    case SYS_getegid:
      printf("getegid()\n");
      break; /*SYS_getegid*/

/***********************************************************************************/ 
    case SYS_setpgid:
      printf("setpgid(pid=%s, pgid=%d)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);
      break; /*SYS_setpgid*/

/***********************************************************************************/ 
    case SYS_getppid:
      printf("getppid()\n");
      break; /*SYS_getppid*/

/***********************************************************************************/ 
    case SYS_getpgrp:
      printf("getpgrp()\n");
      break; /*SYS_getpgrp*/

/***********************************************************************************/ 
    case SYS_setsid:
      printf("setsid()\n");
      break; /*SYS_setsid*/

/***********************************************************************************/ 
    case SYS_setreuid:
      printf("setreuid(uid=%d, euid=%d)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);
      break; /*SYS_setreuid*/

/***********************************************************************************/ 
    case SYS_setregid:
      printf("setregid(gid=%d, egid=%d)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);
      break; /*SYS_setregid*/

/***********************************************************************************/ 
    case SYS_getgroups:
      printf("getgroups(groupentsize=%d, groups-addr=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);
      break; /*SYS_getgroups*/

/***********************************************************************************/ 
    case SYS_setgroups:
      printf("setgroups(groupentsize=%d, groups-addr=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);
      break; /*SYS_setgroups*/

/***********************************************************************************/ 
    case SYS_setresuid:
      printf("setresuid(ruid=%d, euid=%d, suid=%d)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);
      break; /*SYS_setresuid*/

/***********************************************************************************/ 
    case SYS_getresuid:
      // TODO: Progress to syscall exit and receive the actual values.
      printf("getresuid(ruid=%p, euid=%p, suid=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);
      break; /*SYS_getresuid*/

/***********************************************************************************/ 
    case SYS_setresgid:
      printf("setresgid(rgid=%d, egid=%d, sgid=%d)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);
      break; /*SYS_setresgid*/

/***********************************************************************************/ 
    case SYS_getresgid:
      // TODO: Progress to syscall exit and receive the actual values.
      printf("getresgid(rgid=%p, egid=%p, sgid=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);
      break; /*SYS_getresgid*/

/***********************************************************************************/ 
    case SYS_getpgid:
      printf("getpgid(pid=%d)\n",
              executableHandle->regs.rdi);
      break; /*SYS_getpgid*/

/***********************************************************************************/ 
    case SYS_setfsuid:
      printf("setfsuid(uid=%d)\n",
              executableHandle->regs.rdi);
      break; /*SYS_setfsuid*/

/***********************************************************************************/ 
    case SYS_setfsgid:
      printf("setfsgid(gid=%d)\n",
              executableHandle->regs.rdi);
      break; /*SYS_setfsgid*/

/***********************************************************************************/ 
    case SYS_getsid:
      printf("getsid(pid=%d)\n",
              executableHandle->regs.rdi);
      break; /*SYS_getsid*/

/***********************************************************************************/ 
    case SYS_capget:
      // TODO: Look into what data we can get from capget/capset
      printf("capget()\n");
      break; /*SYS_capget*/

/***********************************************************************************/ 
    case SYS_capset:
      printf("capset()\n");
      break; /*SYS_capset*/

/***********************************************************************************/ 
    case SYS_rt_sigpending:
      printf("rt_sigpending(set=%p, sigentsize=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);
      break; /*SYS_rt_sigpending*/

/***********************************************************************************/ 
    case SYS_rt_sigtimedwait:
      printf("rt_sigtimedwait(*uthese=%p, uinfo=%p, *uts=%p, sigentsize=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx,
              executableHandle->regs.r10);
      break; /*SYS_rt_sigtimedwait*/

/***********************************************************************************/ 
    case SYS_rt_sigqueueinfo:
      printf("rt_sigqueueinfo(pid=%d, sig=0x%08x, *uinfo=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);
      break; /*SYS_rt_sigqueueinfo*/

/***********************************************************************************/ 
    case SYS_rt_sigsuspend:
      printf("rt_sigsuspend(*newset=%p, sigentsize=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);
      break; /*SYS_rt_sigsuspend*/
/***********************************************************************************/ 
    case SYS_sigaltstack:
      // TODO we could receive the signal stack at the syscall exit.
      printf("sigaltstack(*uss=%p, *uoss=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);
      break; /*SYS_sigaltstack*/

    case SYS_utime:
      struct utimbuf timeBuff = {0};
      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.rsi,
                                     &timeBuff,
                                     sizeof(struct utimbuf));
                                     
      printf("utime(filename=%s, act-time=%d, mod-time=%d)\n",
              executableHandle->regs.rdi,
              timeBuff.actime,
              timeBuff.modtime);
      break; /*SYS_utime*/

/***********************************************************************************/    
    case SYS_mknod:
      printf("mknod(filename=%s, mode=0x%08x, dev=%d)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);
      break; /*SYS_mknod*/

/***********************************************************************************/    
    case SYS_personality:
      printf("personality(personality=0x%08x)\n",
              executableHandle->regs.rdi);
      break; /*SYS_personality*/

/***********************************************************************************/    
    case SYS_ustat:
      printf("ustat(dev=%d)\n", executableHandle->regs.rdi); // This function is deprecated
      break; /*SYS_ustat*/

/***********************************************************************************/    
    case SYS_statfs:
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid, executableHandle->regs.rdi, &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("statfs(path=\"%s\")\n", tmpBuffer1); // TODO: progress to end of syscall and try to extract statfs struct.
      break; /*SYS_statfs*/

/***********************************************************************************/    
    case SYS_fstatfs:
      printf("fstatfs(fd=%d)\n", executableHandle->regs.rdi); // This function is deprecated
      break; /*SYS_fstatfs*/

/***********************************************************************************/    
    case SYS_sysfs:
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid, executableHandle->regs.rsi, &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("sysfs(option=0x%08x, path=\"%s\")\n", tmpBuffer1);
      break; /*SYS_sysfs*/

/***********************************************************************************/    
    case SYS_getpriority:
      printf("getpriority(which=%d, who=%d)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);
      break; /*SYS_getpriority*/

/***********************************************************************************/    
    case SYS_setpriority:
      printf("setpriority(which=%d, who=%d, priority=%d)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);
      break; /*SYS_setpriority*/

/***********************************************************************************/    
    case SYS_sched_setparam:
      printf("sched_setparam(pid=%d, param-struct=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);
      break; /*SYS_sched_setparam*/

/***********************************************************************************/    
    case SYS_sched_getparam:
      printf("sched_getparam(pid=%d, param-struct=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);
      break; /*SYS_sched_getparam*/

/***********************************************************************************/    
    case SYS_sched_setscheduler:
      printf("sched_setscheduler(pid=%d, policy=%d, param-struct=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);
      break; /*SYS_sched_setscheduler*/

/***********************************************************************************/
    case SYS_sched_getscheduler:
      printf("sched_getscheduler(pid=%d)\n",
              executableHandle->regs.rdi);
      break; /*SYS_sched_getscheduler*/

/***********************************************************************************/
    case SYS_sched_get_priority_max:
      printf("sched_get_priority_max(policy=%d)\n",
              executableHandle->regs.rdi);
      break; /*SYS_sched_get_priority_max*/

/***********************************************************************************/
    case SYS_sched_get_priority_min:
      printf("sched_get_priority_min(policy=%d)\n",
              executableHandle->regs.rdi);
      break; /*SYS_sched_get_priority_min*/

/***********************************************************************************/
    case SYS_sched_rr_get_interval:
      struct timespec ts = {0};
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      err = readProcessMemoryFromPID(executableHandle->pid, &ts, executableHandle->regs.rsi, sizeof(struct timespec));
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("sched_rr_get_interval(pid=%d, tv_sec=%d, tv_nsecs=%d)\n",
              executableHandle->regs.rdi,
              ts.tv_sec,
              ts.tv_nsec);
      break; /*SYS_sched_rr_get_interval*/

    case SYS_mlock:
      printf("mlock(start=0x%08x, length=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);
      break; /*SYS_mlock*/

/***********************************************************************************/
    case SYS_munlock:
      printf("munlock(start=0x%08x, length=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);
      break; /*SYS_munlock*/

/***********************************************************************************/
    case SYS_mlockall:
      printf("mlockall(flags=0x%08x)\n",
              executableHandle->regs.rdi);
      break; /*SYS_mlockall*/

/***********************************************************************************/
    case SYS_munlockall:
      printf("munlockall()\n");
      break; /*SYS_munlockall*/
/***********************************************************************************/
    case SYS_vhangup:
      printf("vhangup()\n");
      break; /*SYS_vhangup*/
/***********************************************************************************/
    case SYS_pivot_root:
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      tmpBuffer2 = malloc(PATH_MAX);
      if(tmpBuffer2 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rsi,
                                        &tmpBuffer2);
      if(err != ERR_NONE)
      {
        return err;
      }
      printf("pivot_root(start=\"%s\", length=\"%s\")\n",
              tmpBuffer1,
              tmpBuffer2);
      break; /*SYS_pivot_root*/
/***********************************************************************************/
    // case SYS_ni_syscall:      // NOT IMPLEMENTED
    //   printf("ni_syscall\n");
    //   break; /*SYS_ni_syscall*/
/***********************************************************************************/
    case SYS_prctl:
      // TODO: Print options in human readable form.
      printf("prctl(option=0x%08x, arg2=0x%016x, arg3=0x%016x, arg3=0x%016x, arg4=0x%016x, arg5=0x%016x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx,
              executableHandle->regs.r10,
              executableHandle->regs.r8,
              executableHandle->regs.r9);
      break; /*SYS_prctl*/
/***********************************************************************************/
    case SYS_adjtimex:
      struct timex tmx = {0};
      err = readProcessMemoryFromPID(executableHandle->pid,
                                     &tmx,
                                     executableHandle->regs.rdi,
                                     sizeof(struct timex));
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("adjtimex(modes=0x%08x)\n", tmx.modes);
      break; /*SYS_adjtimex*/
/***********************************************************************************/
    case SYS_setrlimit:
      struct rlimit rlim = {0};
      err = readProcessMemoryFromPID(executableHandle->pid,
                                     &rlim,
                                     executableHandle->regs.rsi,
                                     sizeof(struct rlimit));
      if(err != ERR_NONE)
      {
        return err;
      }
      
      printf("setrlimit(resource=%d, cur=%d, max=%d)\n", executableHandle->regs.rdi, rlim.rlim_cur, rlim.rlim_max);
      break; /*SYS_setrlimit*/
/***********************************************************************************/
    case SYS_chroot:
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("chroot(filname=\"%s\")\n",
              tmpBuffer1);
     
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_chroot*/

    case SYS_sync:
      printf("sync()\n");
     
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_sync*/

/***********************************************************************************/
    case SYS_acct:
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("acct(filename=\"%s\")\n", tmpBuffer1);
     
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_acct*/

/***********************************************************************************/
    case SYS_settimeofday:
      struct timeval tm = {0};
      err = readProcessMemoryFromPID(executableHandle->pid,
                                     &tm,
                                     executableHandle->regs.rsi,
                                     sizeof(struct timeval));
      if(err != ERR_NONE)
      {
        return err;
      }
      
      printf("settimeofday(seconds=%d, micro-seconds=%d)\n", tm.tv_sec, tm.tv_usec);
    
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_settimeofday*/

/***********************************************************************************/
    case SYS_mount:
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid, executableHandle->regs.rdi, &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      tmpBuffer2 = malloc(PATH_MAX);
      if(tmpBuffer2 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid, executableHandle->regs.rdi, &tmpBuffer2);
      if(err != ERR_NONE)
      {
        return err;
      }

      tmpBuffer3 = malloc(PATH_MAX);
      if(tmpBuffer3 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid, executableHandle->regs.rdi, &tmpBuffer3);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("mount(dev-name=\"%s\", dir-name=\"%s\", type=\"%s\", flags=0x%08x)\n", tm.tv_sec, tm.tv_usec);
      
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_mount*/

/***********************************************************************************/
    case SYS_umount2:
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid, executableHandle->regs.rdi, &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("umount2(name=\"%s\", flags=0x%08x)\n", tmpBuffer1, executableHandle->regs.rsi);
      
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_umount2*/

/***********************************************************************************/
    case SYS_swapon:
      char flags[50] = {0};
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid, executableHandle->regs.rdi, &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      // Get which flag is being used for the swap area
      if((executableHandle->regs.rsi & SWAP_FLAG_PREFER) == SWAP_FLAG_PREFER)
      {
        strncat(flags, "SWAP_FLAG_PREFER", 16);
      }
      if((executableHandle->regs.rsi & SWAP_FLAG_DISCARD) == SWAP_FLAG_DISCARD)
      {
        strncat(flags, "SWAP_FLAG_DISCARD", 16);
      }
      

      printf("swapon(path=\"%s\", flags=\"%s\")\n", tmpBuffer1, executableHandle->regs.rsi);
      
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_swapon*/

/***********************************************************************************/
    case SYS_swapoff:
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid, executableHandle->regs.rdi, &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("swapoff(special-file=\"%s\")\n", tmpBuffer1);
      
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_swapoff*/

/***********************************************************************************/
    case SYS_reboot: // TODO: All SYS_reboot commands are parsed into SYS_sayscall
      char cmd[40];
      switch(executableHandle->regs.rdi)
      {
        case LINUX_REBOOT_CMD_CAD_OFF:
          strncpy(cmd, "LINUX_REBOOT_CMD_CAD_OFF", 24);
          break;

        case LINUX_REBOOT_CMD_CAD_ON:
          strncpy(cmd, "LINUX_REBOOT_CMD_CAD_ON", 23);
          break;

        case LINUX_REBOOT_CMD_HALT:
          strncpy(cmd, "LINUX_REBOOT_CMD_HALT", 21);
          break;

        case LINUX_REBOOT_CMD_KEXEC:
          strncpy(cmd, "LINUX_REBOOT_CMD_KEXEC", 22);
          break;

        case LINUX_REBOOT_CMD_POWER_OFF:
          strncpy(cmd, "LINUX_REBOOT_CMD_POWER_OFF", 26);
          break;

        case LINUX_REBOOT_CMD_RESTART:
          strncpy(cmd, "LINUX_REBOOT_CMD_RESTART", 24);
          break;

        case LINUX_REBOOT_CMD_RESTART2:
          strncpy(cmd, "LINUX_REBOOT_CMD_RESTART2", 25);
          break;

        case LINUX_REBOOT_CMD_SW_SUSPEND:
          strncpy(cmd, "LINUX_REBOOT_CMD_SW_SUSPEND", 27);
          break;
      }

      printf("reboot(cmd=\"%s\")\n", cmd);
      
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_reboot*/

/***********************************************************************************/
    case SYS_sethostname:
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid, executableHandle->regs.rdi, &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("sethostname(name=\"%s\", length=%d)\n", tmpBuffer1, executableHandle->regs.rdi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_sethostname*/

/***********************************************************************************/
    case SYS_setdomainname:
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid, executableHandle->regs.rdi, &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("setdomainname(name=\"%s\", length=%d)\n", tmpBuffer1, executableHandle->regs.rsi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_setdomainname*/

/***********************************************************************************/
    case SYS_ioperm:
      printf("ioperm(from=%d, length=%d, turn-on=%d)\n",
                     executableHandle->regs.rdi,
                     executableHandle->regs.rsi,
                     executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_ioperm*/

/***********************************************************************************/
    case SYS_init_module:
      printf("init_module(umod=%p, length=0x%08x, args-addr=%p)\n",
                          executableHandle->regs.rdi,
                          executableHandle->regs.rsi,
                          executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_init_module*/


/***********************************************************************************/
    case SYS_delete_module:
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("delete_module(name-user=\"%s\", flags=0x%08x)\n",
                            tmpBuffer1,
                            executableHandle->regs.rsi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_delete_module*/

/***********************************************************************************/
    case SYS_quotactl:
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rsi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("quotactl(cmd=0x%08x, flags=0x%08x, id=%d, addr=%p)\n",
                       executableHandle->regs.rdi,
                       tmpBuffer1,
                       executableHandle->regs.rdx,
                       executableHandle->regs.r10);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_quotactl*/

/***********************************************************************************/
    case SYS_gettid:
      printf("gettid()\n");

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_gettid*/

/***********************************************************************************/
    case SYS_readahead:

      printf("readahead(fd=%d, offset=0x%08x, count=0x%08x)\n",
                       executableHandle->regs.rdi,
                       executableHandle->regs.rsi,
                       executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_readahead*/

/***********************************************************************************/
    case SYS_setxattr:
      // Get path argument
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      // Get name argument
      tmpBuffer2 = malloc(PATH_MAX);
      if(tmpBuffer2 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rsi,
                                        &tmpBuffer2);
      if(err != ERR_NONE)
      {
        return err;
      }

      // Get value argument
      tmpBuffer3 = malloc(PATH_MAX);
      if(tmpBuffer3 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readProcessMemoryFromPID(executableHandle->pid, executableHandle->regs.rdx, tmpBuffer3, executableHandle->regs.r10);
      if(err != ERR_NONE)
      {
        return err;
      }

      if(isAsciidata(tmpBuffer3, executableHandle->regs.rdx))
      {
        printf("setxattr(path=\"%s\", key=\"%s\", value=\"%s\", size=0x%08x, flags=0x%08x)\n",
                        tmpBuffer1,
                        tmpBuffer2,
                        tmpBuffer3,
                        executableHandle->regs.rdx,
                        executableHandle->regs.r10);
      }
      else
      {
        printf("setxattr(path=\"%s\", key=\"%s\", value=0x%08x, size=0x%08x, flags=0x%08x)\n",
                        tmpBuffer1,
                        tmpBuffer2,
                        tmpBuffer3,
                        executableHandle->regs.rdx,
                        executableHandle->regs.r10);
      }

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_setxattr*/

/***********************************************************************************/
    case SYS_lsetxattr:
      // Get path argument
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      // Get name argument
      tmpBuffer2 = malloc(PATH_MAX);
      if(tmpBuffer2 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rsi,
                                        &tmpBuffer2);
      if(err != ERR_NONE)
      {
        return err;
      }

      // Get keyValue argument
      tmpBuffer3 = malloc(PATH_MAX);
      if(tmpBuffer3 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readProcessMemoryFromPID(executableHandle->pid, executableHandle->regs.rdx, tmpBuffer3, executableHandle->regs.r10);
      if(err != ERR_NONE)
      {
        return err;
      }

      if(isAsciidata(tmpBuffer3, executableHandle->regs.rdx))
      {
        printf("lsetxattr(path=\"%s\", key=\"%s\", keyValue=\"%s\", size=0x%08x, flags=0x%08x)\n",
                          tmpBuffer1,
                          tmpBuffer2,
                          tmpBuffer3,
                          executableHandle->regs.rdx,
                          executableHandle->regs.r10);
      }
      else
      {
        printf("lsetxattr(path=\"%s\", key=\"%s\", value=0x%0168x, size=0x%08x, flags=0x%08x)\n",
                          tmpBuffer1,
                          tmpBuffer2,
                          tmpBuffer3,
                          executableHandle->regs.rdx,
                          executableHandle->regs.r10);
      }

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_lsetxattr*/

/***********************************************************************************/
    case SYS_fsetxattr:
      // Get name argument
      tmpBuffer2 = malloc(PATH_MAX);
      if(tmpBuffer2 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rsi,
                                        &tmpBuffer2);
      if(err != ERR_NONE)
      {
        return err;
      }

      // Get keyValue argument
      tmpBuffer3 = malloc(PATH_MAX);
      if(tmpBuffer3 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readProcessMemoryFromPID(executableHandle->pid, executableHandle->regs.rdx, tmpBuffer3, executableHandle->regs.r10);
      if(err != ERR_NONE)
      {
        return err;
      }

      if(isAsciidata(tmpBuffer3, executableHandle->regs.rdx))
      {
        printf("fsetxattr(fd=%d, key=\"%s\", keyValue=\"%s\", size=0x%08x, flags=0x%08x)\n",
                          tmpBuffer1,
                          tmpBuffer2,
                          tmpBuffer3,
                          executableHandle->regs.rdx,
                          executableHandle->regs.r10);
      }
      else
      {
        printf("fsetxattr(fd=%d, key=\"%s\", value=0x%016x, size=0x%08x, flags=0x%08x)\n",
                          tmpBuffer1,
                          tmpBuffer2,
                          tmpBuffer3,
                          executableHandle->regs.rdx,
                          executableHandle->regs.r10);
      }

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_fsetxattr*/

/***********************************************************************************/
    case SYS_getxattr:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // Get path argument
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      // Get name argument
      tmpBuffer2 = malloc(PATH_MAX);
      if(tmpBuffer2 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rsi,
                                        &tmpBuffer2);
      if(err != ERR_NONE)
      {
        return err;
      }

      // Get keyValue argument
      tmpBuffer3 = malloc(PATH_MAX);
      if(tmpBuffer3 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readProcessMemoryFromPID(executableHandle->pid, executableHandle->regs.rdx, tmpBuffer3, executableHandle->regs.r10);
      if(err != ERR_NONE)
      {
        return err;
      }

      if(isAsciidata(tmpBuffer3, executableHandle->regs.rdx))
      {
        printf("getxattr(path=\"%s\", key=\"%s\", keyValue=\"%s\", size=0x%08x)\n",
                          tmpBuffer1,
                          tmpBuffer2,
                          tmpBuffer3,
                          executableHandle->regs.rdx);
      }
      else
      {
        printf("getxattr(path=\"%s\", key=\"%s\", value=0x%016x, size=0x%08x)\n",
                          tmpBuffer1,
                          tmpBuffer2,
                          tmpBuffer3,
                          executableHandle->regs.rdx);
      }

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getxattr*/

/***********************************************************************************/
    case SYS_lgetxattr:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // Get path argument
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      // Get name argument
      tmpBuffer2 = malloc(PATH_MAX);
      if(tmpBuffer2 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rsi,
                                        &tmpBuffer2);
      if(err != ERR_NONE)
      {
        return err;
      }

      // Get keyValue argument
      tmpBuffer3 = malloc(PATH_MAX);
      if(tmpBuffer3 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readProcessMemoryFromPID(executableHandle->pid, executableHandle->regs.rdx, tmpBuffer3, executableHandle->regs.r10);
      if(err != ERR_NONE)
      {
        return err;
      }

      if(isAsciidata(tmpBuffer3, executableHandle->regs.rdx))
      {
        printf("lgetxattr(path=\"%s\", key=\"%s\", keyValue=\"%s\", size=0x%08x)\n",
                          tmpBuffer1,
                          tmpBuffer2,
                          tmpBuffer3,
                          executableHandle->regs.rdx);
      }
      else
      {
        printf("lgetxattr(path=\"%s\", key=\"%s\", value=0x%016x, size=0x%08x)\n",
                          tmpBuffer1,
                          tmpBuffer2,
                          tmpBuffer3,
                          executableHandle->regs.rdx);
      }

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_lgetxattr*/

/***********************************************************************************/
    case SYS_fgetxattr:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // Get name argument
      tmpBuffer2 = malloc(PATH_MAX);
      if(tmpBuffer2 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rsi,
                                        &tmpBuffer2);
      if(err != ERR_NONE)
      {
        return err;
      }

      // Get keyValue argument
      tmpBuffer3 = malloc(PATH_MAX);
      if(tmpBuffer3 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readProcessMemoryFromPID(executableHandle->pid, executableHandle->regs.rdx, tmpBuffer3, executableHandle->regs.r10);
      if(err != ERR_NONE)
      {
        return err;
      }

      if(isAsciidata(tmpBuffer3, executableHandle->regs.rdx))
      {
        printf("fgetxattr(path=%d, key=\"%s\", keyValue=\"%s\", size=0x%08x)\n",
                          executableHandle->regs.rdi,
                          tmpBuffer2,
                          tmpBuffer3,
                          executableHandle->regs.rdx);
      }
      else
      {
        printf("fgetxattr(path=%d, key=\"%s\", value=0x%016x, size=0x%08x)\n",
                          executableHandle->regs.rdi,
                          tmpBuffer2,
                          tmpBuffer3,
                          executableHandle->regs.rdx);
      }

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_fgetxattr*/

/***********************************************************************************/
    case SYS_listxattr:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // Get name argument
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("listxattr(path=\"%s\", list-addr=%p, list-size=%d)\n",
                        tmpBuffer1,
                        executableHandle->regs.rsi,
                        executableHandle->regs.rdx);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_listxattr*/

/***********************************************************************************/
    case SYS_llistxattr:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // Get name argument
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("llistxattr(path=\"%s\", list-addr=%p, list-size=%d)\n",
                        tmpBuffer1,
                        executableHandle->regs.rsi,
                        executableHandle->regs.rdx);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_llistxattr*/

/***********************************************************************************/
    case SYS_flistxattr:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      printf("flistxattr(fd=%d, list-addr=%p, list-size=%d)\n",
                        executableHandle->regs.rdi,
                        executableHandle->regs.rsi,
                        executableHandle->regs.rdx);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_flistxattr*/

/***********************************************************************************/
    case SYS_removexattr:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      // Get path argument
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      // Get name argument
      tmpBuffer2 = malloc(PATH_MAX);
      if(tmpBuffer2 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rsi,
                                        &tmpBuffer2);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("removexattr(path=\"%s\", name=\"%s\")\n",
                          tmpBuffer1,
                          tmpBuffer2);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_removexattr*/

/***********************************************************************************/
    case SYS_lremovexattr:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      // Get path argument
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      // Get name argument
      tmpBuffer2 = malloc(PATH_MAX);
      if(tmpBuffer2 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rsi,
                                        &tmpBuffer2);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("lremovexattr(path=\"%s\", name=\"%s\")\n",
                          tmpBuffer1,
                          tmpBuffer2);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_lremovexattr*/

/***********************************************************************************/
    case SYS_fremovexattr:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      // Get name argument
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rsi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("fremovexattr(fd=%d, name=\"%s\")\n",
                           executableHandle->regs.rdi,
                           tmpBuffer2);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_fremovexattr*/

/***********************************************************************************/
    case SYS_tkill:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      printf("tkill(pid=%d, signal=0x%08x)\n",
                    executableHandle->regs.rdi,
                    tmpBuffer2);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_tkill*/

/***********************************************************************************/
    case SYS_time:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      printf("time()\n");

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_time*/

/***********************************************************************************/
    case SYS_futex:
      char options[200] = {0};
      uint8_t optionsUsed = 0;
      struct timespec tmSpec = {0};
      uint32_t uAddr1 = 0;
      uint32_t uAddr2 = 0;

      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.rdi,
                                     &uAddr1,
                                     sizeof(uint32_t));
      if(err != ERR_NONE)
      {
        return err;
      }

      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.r8,
                                     &uAddr1,
                                     sizeof(uint32_t));
      if(err != ERR_NONE)
      {
        return err;
      }

      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.r10,
                                     &tmSpec,
                                     sizeof(struct timespec));
      if(err != ERR_NONE)
      {
        return err;
      }

      // TODO: We should print the option argument as their respective macros in the future.
      // We may not have taken all cases into account.
      if((executableHandle->regs.rsi) == 0)
      {
        strncat(options, "FUTEX_OP_SET", 12);
        optionsUsed++;
      }
      else if((executableHandle->regs.rsi & FUTEX_OP_ADD) == FUTEX_OP_ADD)
      {
        if(optionsUsed > 0)
        {
          strncat(options, " | ", 3);
        }
        strncat(options, "FUTEX_OP_SET", 12);
        optionsUsed++;
      }
      else if((executableHandle->regs.rsi & FUTEX_OP_OR) == FUTEX_OP_OR)
      {
        if(optionsUsed > 0)
        {
          strncat(options, " | ", 3);
        }
        strncat(options, "FUTEX_OP_OR", 11);
        optionsUsed++;
      }
      else if((executableHandle->regs.rsi & FUTEX_OP_ANDN) == FUTEX_OP_ANDN)
      {
        if(optionsUsed > 0)
        {
          strncat(options, " | ", 3);
        }
        strncat(options, "FUTEX_OP_ANDN", 13);
        optionsUsed++;
      }
      else if((executableHandle->regs.rsi & FUTEX_OP_XOR) == FUTEX_OP_XOR)
      {
        if(optionsUsed > 0)
        {
          strncat(options, " | ", 3);
        }
        strncat(options, "FUTEX_OP_XOR", 12);
        optionsUsed++;
      }

      printf("futex(uAddr1=%p, options=\"%s\", value=0x%08x, time-seconds=%d, time-nano-seconds=%d, uAddr2=%p, value3=%d)\n",
                    uAddr1,
                    executableHandle->regs.rsi,
                    executableHandle->regs.rdx,
                    tmSpec.tv_sec,
                    tmSpec.tv_nsec,
                    uAddr2,
                    executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_futex*/

/***********************************************************************************/
    case SYS_sched_setaffinity:

      printf("sched_setaffinity(pid=%d, length=0x%08x, cpu-set-addr=%p)\n",\
                          executableHandle->regs.rdi,
                          executableHandle->regs.rsi,
                          executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_sched_setaffinity*/

/***********************************************************************************/
    case SYS_sched_getaffinity:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("sched_getaffinity(pid=%d, length=0x%08x, cpu-set-addr=%p)\n",\
                                executableHandle->regs.rdi,
                                executableHandle->regs.rsi,
                                executableHandle->regs.rdx);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_sched_getaffinity*/

/***********************************************************************************/
    case SYS_io_setup:
      printf("io_setup(nr_events=0x%08x, ctx-addr=%p)\n",\
                       executableHandle->regs.rdi,
                       executableHandle->regs.rsi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_io_setup*/

/***********************************************************************************/
    case SYS_io_destroy:
      uint64_t ctx = 0;

      err = readProcessMemoryFromPID(executableHandle->pid, executableHandle->regs.rdi, &ctx, sizeof(uint64_t));
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("io_destroy(ctx=0x%016x)\n", ctx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_io_destroy*/

/***********************************************************************************/
    case SYS_io_getevents:
      uint64_t ctx2 = 0;
      struct io_event ioEvent = {0};
      struct timespec timeout = {0};
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      err = readProcessMemoryFromPID(executableHandle->pid, executableHandle->regs.rdi, &ctx2, sizeof(uint64_t));
      if(err != ERR_NONE)
      {
        return err;
      }

      err = readProcessMemoryFromPID(executableHandle->pid, executableHandle->regs.r10, &ioEvent, sizeof(struct io_event));
      if(err != ERR_NONE)
      {
        return err;
      }

      err = readProcessMemoryFromPID(executableHandle->pid, executableHandle->regs.r8, &timeout, sizeof(struct timespec));
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("io_getevents(ctx=0x%016x, min_nr=%ld, nr=%ld, ioEvent-data=%ld, ioEvent-obj-%ld" \
              "ioEvent-res=%lu, ioEvent-res2=%lu, timeout-seconds=%lu, timeout-nanoseconds=%lu\n",
              ctx,
              executableHandle->regs.rsi,
              executableHandle->regs.rax,
              ioEvent.data,
              ioEvent.obj,
              ioEvent.res,
              ioEvent.res2,
              timeout.tv_sec,
              timeout.tv_nsec);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_io_getevents*/






  }

  free(tmpBuffer3);
  free(tmpBuffer2);
  free(tmpBuffer1);

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
        // TODO: Remove this section and print return code in lookup switch table.
        printf("Returned With: %d\n\n", executableHandle->regs.rax);
      }

      oldRegisters = executableHandle->regs;

      /* Continue to the next syscall. */        
      ptrace(PTRACE_SYSCALL, executableHandle->pid, NULL, NULL);
    }

  } while(executableHandle->isExecuting);

  return ERR_NONE;
}

int8_t launchTraceProgram(ELF_EXECUTABLE_T * executableHandle, int childArgc, const char** childArgs, const char** envp)
{
  ELF64_EXECUTABLE_HANDLE_T * tmpHandle = NULL;
  int8_t err = ERR_NONE;

  if(executableHandle == NULL)
  {
    #ifdef DEBUG
    perror("ERROR null parameter passed to launchTraceProgram()");
    #endif
    return ERR_NULL_ARGUMENT;
  }

  // We cast arbitrarily to 64 bit here just for the switch condition.
  tmpHandle = (ELF64_EXECUTABLE_HANDLE_T *) executableHandle;
  switch (tmpHandle->ehdr->e_ident[EI_CLASS])
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

int8_t mapELF32ToHandleFromProcessMemory(const void ** pMem, ELF32_EXECUTABLE_HANDLE_T ** elfHandle, const uint64_t uCount)
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

  if((*elfHandle) == NULL)
  {
    #ifdef DEBUG
    perror("ERROR allocating memory in mapELF64ToHandleFromProcessMemory()");
    #endif
    return ERR_MEMORY_ALLOCATION_FAILED;
  }
  
  if(uCount == 0)
  {
    #ifdef DEBUG
    perror("ERROR invalid parameter in mapELF64ToHandleFromProcessMemory()");
    #endif
    return ERR_INVALID_ARGUMENT;
  }

  (*elfHandle)->pTextSeg = *pMem;
  
  (*elfHandle)->textSegSize = uCount;
  (*elfHandle)->isExecuting = TRUE;
  
  /* Point the all headers to there respective offsets. */
  (*elfHandle)->ehdr  = (Elf32_Ehdr *)  (*elfHandle)->pTextSeg;
  (*elfHandle)->phdr  = (Elf32_Phdr *) &(*elfHandle)->pTextSeg[ (*elfHandle)->ehdr->e_phoff ];
  
  if((*elfHandle)->ehdr->e_shoff     == 0 ||
     (*elfHandle)->ehdr->e_shnum     == 0 ||
     (*elfHandle)->ehdr->e_shentsize == 0)
  {
    err = ERR_ELF_BINARY_STRIPPED;
  }
  else
  {
    (*elfHandle)->shdr  = (Elf32_Shdr *) &(*elfHandle)->pTextSeg[ (*elfHandle)->ehdr->e_shoff ];
  }
  
  return ERR_NONE;
}

int8_t mapELF64ToHandleFromProcessMemory(const void ** pMem, ELF64_EXECUTABLE_HANDLE_T ** elfHandle, const uint64_t uCount)
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

  if((*elfHandle) == NULL)
  {
    #ifdef DEBUG
    perror("ERROR allocating memory in mapELF64ToHandleFromProcessMemory()");
    #endif
    return ERR_MEMORY_ALLOCATION_FAILED;
  }
  
  if(uCount == 0)
  {
    #ifdef DEBUG
    perror("ERROR invalid parameter in mapELF64ToHandleFromProcessMemory()");
    #endif
    return ERR_INVALID_ARGUMENT;
  }

  (*elfHandle)->pTextSeg = *pMem;
  // memcpy((*elfHandle)->pTextSeg, (*pMem), uCount);
  
  (*elfHandle)->textSegSize = uCount;
  (*elfHandle)->isExecuting = TRUE;
  
  /* Point the all headers to there respective offsets. */
  (*elfHandle)->ehdr  = (Elf64_Ehdr *)  (*elfHandle)->pTextSeg;
  (*elfHandle)->phdr  = (Elf64_Phdr *) &(*elfHandle)->pTextSeg[ (*elfHandle)->ehdr->e_phoff ];
  
  if((*elfHandle)->ehdr->e_shoff     == 0 ||
     (*elfHandle)->ehdr->e_shnum     == 0 ||
     (*elfHandle)->ehdr->e_shentsize == 0)
  {
    err = ERR_ELF_BINARY_STRIPPED;
  }
  else
  {
    (*elfHandle)->shdr  = (Elf64_Shdr *) &(*elfHandle)->pTextSeg[ (*elfHandle)->ehdr->e_shoff ];
  }
  
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
    0x02, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x70, 0x10, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    0xe0, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x20, 0x00, 0x0b, 0x00, 0x28, 0x00,
    0x1e, 0x00, 0x1d, 0x00, 0x06, 0x40
  };

  ELF32_EXECUTABLE_HANDLE_T * handle  = NULL;
  char * pData = buff;
  int8_t err   = ERR_NONE;

  handle = malloc(sizeof(ELF64_EXECUTABLE_HANDLE_T));

  err = mapELF32ToHandleFromProcessMemory(&pData, &handle, sizeof(buff));
  assert(err == ERR_NONE);
  assert(handle->ehdr->e_ident[EI_DATA] == ELFDATA2LSB);
  assert(handle->ehdr->e_ident[EI_VERSION] == EV_CURRENT);
  assert(handle->ehdr->e_type == ET_EXEC);
  assert(handle->ehdr->e_machine == EM_386);
  assert(handle->ehdr->e_version == EV_CURRENT);
  assert(handle->ehdr->e_entry == 0x1070);
  assert(handle->ehdr->e_phoff == 0x34);
  assert(handle->ehdr->e_shoff == 0x35e0);
  assert(handle->ehdr->e_phentsize == 0x20);
  assert(handle->ehdr->e_phnum == 0x0B);
  assert(handle->ehdr->e_shentsize == 0x28);
  assert(handle->ehdr->e_shnum == 0x1e);
  assert(handle->ehdr->e_shstrndx == 0x1d);
  assert(handle->isExecuting == TRUE);

  free(handle);
}

void unittest_mapELF32ToHandleFromProcessMemory_legalEhdr_differentValues()
{
  /*
   * Typical Elf32_Ehdr (Different Values)
  */
  char buff[] =
  {
    0x7f, 0x45, 0x4c, 0x46, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x70, 0x10, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    0xe0, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x20, 0x00, 0x0b, 0x00, 0x28, 0x00,
    0x1e, 0x00, 0x1d, 0x00, 0x06, 0x40
  };

  ELF32_EXECUTABLE_HANDLE_T * handle  = NULL;
  char * pData = buff;
  int8_t err   = ERR_NONE;

  handle = malloc(sizeof(ELF64_EXECUTABLE_HANDLE_T));

  err = mapELF32ToHandleFromProcessMemory(&pData, &handle, sizeof(buff));
  assert(err == ERR_NONE);
  assert(handle->ehdr->e_ident[EI_DATA] == ELFDATA2MSB);
  assert(handle->ehdr->e_ident[EI_VERSION] == EV_NONE);
  assert(handle->ehdr->e_type == ET_DYN);
  assert(handle->ehdr->e_machine == EM_386);
  assert(handle->ehdr->e_version == EV_CURRENT);
  assert(handle->ehdr->e_entry == 0x1070);
  assert(handle->ehdr->e_phoff == 0x34);
  assert(handle->ehdr->e_shoff == 0x35e0);
  assert(handle->ehdr->e_phentsize == 0x20);
  assert(handle->ehdr->e_phnum == 0x0B);
  assert(handle->ehdr->e_shentsize == 0x28);
  assert(handle->ehdr->e_shnum == 0x1e);
  assert(handle->ehdr->e_shstrndx == 0x1d);
  assert(handle->isExecuting == TRUE);

  free(handle);
}

void unittest_mapELF32ToHandleFromProcessMemory_nullMemoryPtr()
{
  char * ptr = NULL;
  ELF32_EXECUTABLE_HANDLE_T * handle  = NULL;
  int8_t err   = ERR_NONE;

  err = mapELF32ToHandleFromProcessMemory(&ptr, &handle, 1);
  assert(err == ERR_NULL_ARGUMENT);
  assert(handle == NULL);

  err = mapELF32ToHandleFromProcessMemory(NULL, &handle, 1);
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
    0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x90, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x3d, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x0d, 0x00, 0x40, 0x00, 0x25, 0x00, 0x24, 0x00
  };

  ELF64_EXECUTABLE_HANDLE_T * handle  = NULL;
  char * pData = buff;
  int8_t err   = ERR_NONE;

  handle = malloc(sizeof(ELF64_EXECUTABLE_HANDLE_T));

  err = mapELF64ToHandleFromProcessMemory(&pData, &handle, sizeof(buff));
  assert(err == ERR_NONE);
  assert(handle->ehdr->e_ident[EI_DATA] == ELFDATA2LSB);
  assert(handle->ehdr->e_ident[EI_VERSION] == EV_CURRENT);
  assert(handle->ehdr->e_type == ET_EXEC);
  assert(handle->ehdr->e_machine == EM_X86_64);
  assert(handle->ehdr->e_version == EV_CURRENT);
  assert(handle->ehdr->e_entry == 0x1290);
  assert(handle->ehdr->e_phoff == 0x40);
  assert(handle->ehdr->e_shoff == 0x23d88);
  assert(handle->ehdr->e_phentsize == 0x38);
  assert(handle->ehdr->e_phnum == 13);
  assert(handle->ehdr->e_shentsize == 0x40);
  assert(handle->ehdr->e_shnum == 37);
  assert(handle->ehdr->e_shstrndx == 36);
  assert(handle->isExecuting == TRUE);

  free(handle);
}

void unittest_mapELF64ToHandleFromProcessMemory_legalEhdr_differentValues()
{
  /*
   * Typical Elf64_Ehdr (Different values)
  */
  char buff[] =
  {
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0xfa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x99, 0x99, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x5F, 0x00, 0x0d, 0x00, 0x40, 0x00, 0x27, 0x00, 0x10, 0x00
  };

  ELF64_EXECUTABLE_HANDLE_T * handle  = NULL;
  char * pData = buff;
  int8_t err   = ERR_NONE;

  handle = malloc(sizeof(ELF64_EXECUTABLE_HANDLE_T));

  err = mapELF64ToHandleFromProcessMemory(&pData, &handle, sizeof(buff));
  assert(err == ERR_NONE);
  assert(handle->ehdr->e_ident[EI_DATA] == ELFDATA2MSB);
  assert(handle->ehdr->e_ident[EI_VERSION] == EV_NONE);
  assert(handle->ehdr->e_type == ET_CORE);
  assert(handle->ehdr->e_machine == EM_X86_64);
  assert(handle->ehdr->e_version == EV_NONE);
  assert(handle->ehdr->e_entry == 0xFA78);
  assert(handle->ehdr->e_phoff == 0x80);
  assert(handle->ehdr->e_shoff == 0x99999);
  assert(handle->ehdr->e_phentsize == 0x5F);
  assert(handle->ehdr->e_phnum == 13);
  assert(handle->ehdr->e_shentsize == 0x40);
  assert(handle->ehdr->e_shnum == 39);
  assert(handle->ehdr->e_shstrndx == 16);
  assert(handle->isExecuting == TRUE);

  free(handle);
}

void unittest_mapELF64ToHandleFromProcessMemory_nullMemoryPtr()
{
  char * ptr = NULL;
  ELF64_EXECUTABLE_HANDLE_T * handle  = NULL;
  int8_t err   = ERR_NONE;

  err = mapELF64ToHandleFromProcessMemory(&ptr, &handle, 1);
  assert(err == ERR_NULL_ARGUMENT);
  assert(handle == NULL);

  err = mapELF64ToHandleFromProcessMemory(NULL, &handle, 1);
  assert(err == ERR_NULL_ARGUMENT);
  assert(handle == NULL);

  /* TODO: Add case where uCount == 0 */
}



void elfDynamicTestSuite()
{
  unittest_printMmapFlags();
  unittest_isRepeatedSyscallX64_legalUsage();

  unittest_mapELF32ToHandleFromProcessMemory_legalEhdr();
  unittest_mapELF32ToHandleFromProcessMemory_legalEhdr_differentValues();
  unittest_mapELF32ToHandleFromProcessMemory_nullMemoryPtr();

  unittest_mapELF64ToHandleFromProcessMemory_legalEhdr();
  unittest_mapELF64ToHandleFromProcessMemory_legalEhdr_differentValues();
  unittest_mapELF64ToHandleFromProcessMemory_nullMemoryPtr();
}
#endif /* UNITTEST */