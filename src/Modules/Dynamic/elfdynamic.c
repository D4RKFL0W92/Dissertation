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

static int getKeyctlOperation(int cmd, char * operationBuff)
{
  char tmpBuff[40];

  if(operationBuff == NULL)
  {
    return ERR_NULL_ARGUMENT;
  }

  switch(cmd)
  {
    case KEYCTL_GET_KEYRING_ID:
      strncpy(operationBuff, "KEYCTL_GET_KEYRING_ID", 21);
      break;

    case KEYCTL_JOIN_SESSION_KEYRING:
      strncpy(operationBuff, "KEYCTL_JOIN_SESSION_KEYRING", 27);
      break;

    case KEYCTL_UPDATE:
      strncpy(operationBuff, "KEYCTL_UPDATE", 13);
      break;

    case KEYCTL_REVOKE:
      strncpy(operationBuff, "KEYCTL_REVOKE", 13);
      break;

    case KEYCTL_CHOWN:
      strncpy(operationBuff, "KEYCTL_CHOWN", 12);
      break;

    case KEYCTL_SETPERM:
      strncpy(operationBuff, "KEYCTL_SETPERM", 14);
      break;

    case KEYCTL_DESCRIBE:
      strncpy(operationBuff, "KEYCTL_DESCRIBE", 15);
      break;

    case KEYCTL_CLEAR:
      strncpy(operationBuff, "KEYCTL_CLEAR", 12);
      break;

    case KEYCTL_LINK:
      strncpy(operationBuff, "KEYCTL_LINK", 11);
      break;

    case KEYCTL_UNLINK:
      strncpy(operationBuff, "KEYCTL_UNLINK", 13);
      break;

    case KEYCTL_SEARCH:
      strncpy(operationBuff, "KEYCTL_SEARCH", 13);
      break;

    case KEYCTL_READ:
      strncpy(operationBuff, "KEYCTL_READ", 11);
      break;

    case KEYCTL_INSTANTIATE:
      strncpy(operationBuff, "KEYCTL_INSTANTIATE", 18);
      break;

    case KEYCTL_NEGATE:
      strncpy(operationBuff, "KEYCTL_NEGATE", 13);
      break;

    case KEYCTL_SET_REQKEY_KEYRING:
      strncpy(operationBuff, "KEYCTL_SET_REQKEY_KEYRING", 25);
      break;

    case KEYCTL_SET_TIMEOUT:
      strncpy(operationBuff, "KEYCTL_SET_TIMEOUT", 18);
      break;

    case KEYCTL_ASSUME_AUTHORITY:
      strncpy(operationBuff, "KEYCTL_ASSUME_AUTHORITY", 23);
      break;

    case KEYCTL_GET_SECURITY:
      strncpy(operationBuff, "KEYCTL_GET_SECURITY", 19);
      break;

    case KEYCTL_SESSION_TO_PARENT:
      strncpy(operationBuff, "KEYCTL_SESSION_TO_PARENT", 24);
      break;

    case KEYCTL_REJECT:
      strncpy(operationBuff, "KEYCTL_REJECT", 13);
      break;

    case KEYCTL_INSTANTIATE_IOV:
      strncpy(operationBuff, "KEYCTL_INSTANTIATE_IOV", 22);
      break;

    case KEYCTL_INVALIDATE:
      strncpy(operationBuff, "KEYCTL_INVALIDATE", 17);
      break;

    case KEYCTL_GET_PERSISTENT:
      strncpy(operationBuff, "KEYCTL_GET_PERSISTENT", 21);
      break;

    case KEYCTL_DH_COMPUTE:
      strncpy(operationBuff, "KEYCTL_DH_COMPUTE", 17);
      break;

    case KEYCTL_PKEY_QUERY:
      strncpy(operationBuff, "KEYCTL_PKEY_QUERY", 17);
      break;

    case KEYCTL_PKEY_ENCRYPT:
      strncpy(operationBuff, "KEYCTL_PKEY_ENCRYPT", 19);
      break;

    case KEYCTL_PKEY_DECRYPT:
      strncpy(operationBuff, "KEYCTL_PKEY_DECRYPT", 19);
      break;

    case KEYCTL_PKEY_SIGN:
      strncpy(operationBuff, "KEYCTL_PKEY_SIGN", 16);
      break;

    case KEYCTL_PKEY_VERIFY:
      strncpy(operationBuff, "KEYCTL_PKEY_VERIFY", 18);
      break;

    case KEYCTL_RESTRICT_KEYRING:
      strncpy(operationBuff, "KEYCTL_RESTRICT_KEYRING", 23);
      break;

    case KEYCTL_MOVE:
      strncpy(operationBuff, "KEYCTL_MOVE", 11);
      break;

    case KEYCTL_CAPABILITIES:
      strncpy(operationBuff, "KEYCTL_CAPABILITIES", 19);
      break;

    case KEYCTL_WATCH_KEY:
      strncpy(operationBuff, "KEYCTL_WATCH_KEY", 16);
      break;
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

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_write*/

/***********************************************************************************/
    case SYS_open:
      err = readStringFromProcessMemory(executableHandle->pid, executableHandle->regs.rdi, &tmpBuffer1);
      printf("open(path=%s)\n", tmpBuffer1);
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_open*/

/***********************************************************************************/
    case SYS_close:
      printf("close(fd=%d)\n", executableHandle->regs.rdi);
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_close*/

/***********************************************************************************/
    case SYS_stat:
/***********************************************************************************/
    case SYS_lstat:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      err = readStringFromProcessMemory(executableHandle->pid, executableHandle->regs.rdi, &tmpBuffer1);

      printf("stat(path=\"%s\", struct=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*stat/lstat*/

/***********************************************************************************/
    case SYS_fstat:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // TODO: Read stat struct
      printf("fstat(fd=%d, struct=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break;

/***********************************************************************************/
    case SYS_poll:
      printf("poll(pollfd=%p, nfds=%d, timeout=%d)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_poll*/

/***********************************************************************************/
    case SYS_lseek:
      printf("lseek(fd=%d, offset=%p, whence=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_mmap*/

/***********************************************************************************/
    case SYS_mprotect:
      printf("mprotect(start=%p, size=0x%08x, protections=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_mprotect*/

/***********************************************************************************/
    case SYS_munmap:
      printf("munmap(address=%p, size=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_munmap*/

/***********************************************************************************/
    case SYS_brk:
      printf("brk(brk=0x%08x)\n", executableHandle->regs.rdi);
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_brk*/

/***********************************************************************************/
    case SYS_rt_sigaction:
      printf("rt_sigaction(signum=%d, sig-new-action=0x%08x, " \
             "sig-old-action=0x%08x, size=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx,
              executableHandle->regs.r10);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_rt_sigaction*/

/***********************************************************************************/
    case SYS_rt_sigprocmask:
      printf("rt_sigprocmask(how=%d, sig-new-set=0x%08x, " \
            "sig-old-set=0x%08x, size=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx,
              executableHandle->regs.r10);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_rt_sigprocmask*/

/***********************************************************************************/
    case SYS_rt_sigreturn:
      printf("rt_sigreturn()\n");

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_rt_sigreturn*/

/***********************************************************************************/
    case SYS_ioctl:
      printf("ioctl(fd=%d, cmd=%d, arg=%ld)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
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

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_pwrite64*/

/***********************************************************************************/
    case SYS_readv:
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
      printf("readv(fd=%d, iovec=%p, vec-len=0x%08x)\n", // TODO: Check if it's even possible to read iovec?
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_writev*/

/***********************************************************************************/
    case SYS_access:
      err = readStringFromProcessMemory(executableHandle->pid, executableHandle->regs.rdi, &tmpBuffer1);
      printf("access(filename=\"%s\", mode=0x%08x)\n",
              tmpBuffer1,
              executableHandle->regs.rsi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_access*/

/***********************************************************************************/
    case SYS_pipe:
      printf("pipe(fd=%d)\n",
        executableHandle->regs.rdi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_pipe*/

/***********************************************************************************/
    case SYS_select:
      printf("select(n=%d, inp=%p, outp=%p, exp=%p, timeval=%ld)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10,
        executableHandle->regs.r8);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_select*/

/***********************************************************************************/
    case SYS_sched_yield:
      printf("sched_yield()\n");
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_mremap*/

/***********************************************************************************/
    case SYS_msync:
      printf("msync(start=%ld, size=0x%08x, flags=",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);
      printMsyncFlags(executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_msync*/

/***********************************************************************************/
    case SYS_mincore:
      printf("mincore(addr=%p, size=0x%08x, vec=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_mincore*/

/***********************************************************************************/
    case SYS_madvise:
    /*TODO: Print the bahaviour arguments.*/
      printf("madvise(start=%p, length=0x%08x, behaviour=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_madvise*/

/***********************************************************************************/
    case SYS_shmget:
      printf("shmget(key=0x%08x, size=0x%08x, flag=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_shmctl*/

/***********************************************************************************/
    case SYS_dup:
      printf("dup(fd=%d)\n", executableHandle->regs.rdi);
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_dup*/

/***********************************************************************************/
    case SYS_dup2:
      printf("dup2(id=%d, cmd=%d)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_dup2*/

/***********************************************************************************/
    case SYS_pause:
      printf("pause()\n");
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_pause*/

/***********************************************************************************/
    case SYS_nanosleep:
      printf("nanosleep()\n");
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_nanosleep*/

    /*
     * TODO: Write code to read itimer value from struct. This
     * is relavent for most timer related syscalls.
    */
/***********************************************************************************/
    case SYS_getitimer:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // TODO: Get value from address.
      printf("getitimer(which=%d, valueAddr=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getitimer*/

/***********************************************************************************/
    case SYS_alarm:
      printf("alarm(seconds=%d)\n",
        executableHandle->regs.rdi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_alarm*/

/***********************************************************************************/
    case SYS_setitimer:
      printf("getitimer(which=%d, valueAddr=%p, ovalueAddr=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_setitimer*/

/***********************************************************************************/
    case SYS_getpid:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // TODO: get the returned pid if it is not the return code.
      printf("getpid()\n");

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getpid*/

/***********************************************************************************/
    case SYS_sendfile:
      printf("sendfile(out_fd=%d, in_fd=%d, offset=%p, count=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_sendfile*/

/***********************************************************************************/
    case SYS_socket:
      printf("sendfile(domain=%d, type=%d, protocol=%d)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_socket*/

/***********************************************************************************/
    case SYS_connect:
      printf("connect(sock_fd=%d, addr=%p, protocol=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_connect*/

/***********************************************************************************/
    case SYS_accept:
      printf("accept(sock_fd=%d, addr=%p, protocol=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_sendto*/

/***********************************************************************************/
    case SYS_recvfrom:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
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

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_recvfrom*/

/***********************************************************************************/
    case SYS_sendmsg:
      printf("sendmsg(sock_fd=%d, buffAddr=%p, flags=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_sendmsg*/

/***********************************************************************************/
    case SYS_recvmsg:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // TODO: Read the message from buffer address.
      printf("recvmsg(sock_fd=%d, buffAddr=%p, flags=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_recvmsg*/

/***********************************************************************************/
    case SYS_shutdown:
      printf("shutdown(sock_fd=%d, how=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_shutdown*/

/***********************************************************************************/
    case SYS_bind:
      printf("bind(sock_fd=%d, addr=%p, addrLen=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_bind*/

/***********************************************************************************/
    case SYS_listen:
      printf("listen(sock_fd=%d, backlog=%d)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);
      break; /*SYS_listen*/

/***********************************************************************************/
    case SYS_getsockname:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // TODO: read the address.
      printf("getsockname(sock_fd=%d, addr=%p, addrLen=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getsockname*/

/***********************************************************************************/
    case SYS_getpeername:
      printf("getpeername(sock_fd=%d, addr=%p, addrLen=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getpeername*/

/***********************************************************************************/
    case SYS_socketpair:
      printf("socketpair(domain=%d, type=%d, protocol=%d, sv=%d)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_socketpair*/

/***********************************************************************************/
    case SYS_setsockopt:
      printf("setsockopt(fd=%d, level=%d, optname=%d, optval=%p, optlen=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10,
        executableHandle->regs.r8);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_setsockopt*/

/***********************************************************************************/
    case SYS_getsockopt:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // TODO: Get sock options
      printf("getsockopt(fd=%d, level=%d, optname=%d, optval=%p, optlen=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10,
        executableHandle->regs.r8);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getsockopt*/

/***********************************************************************************/
    case SYS_clone:
      printf("clone(funcPtr=%p, stack=%p, flags=0x%08x, arg=%p, parent_tid=%d)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10,
        executableHandle->regs.r8);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_clone*/

/***********************************************************************************/
    case SYS_fork:
      printf("fork()\n");

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_fork*/

/***********************************************************************************/
    case SYS_vfork:
      printf("vfork()\n");

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_execve*/

/***********************************************************************************/
    case SYS_exit:
      printf("exit(errcode=%d)\n",
        executableHandle->regs.rdi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_exit*/

/***********************************************************************************/
    case SYS_wait4:
      printf("clone(pid=%d, status=%p, options=0x%08x, rusage=%p)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_clone*/

/***********************************************************************************/
    case SYS_kill:
      printf("kill(pid=%d, signal=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_kill*/

/***********************************************************************************/
    case SYS_uname:
      printf("uname(pid=%p)\n",
        executableHandle->regs.rdi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_uname*/

/***********************************************************************************/
    case SYS_semget:
      printf("semget(key=%d, nsems=%d, semflags=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_semget*/

/***********************************************************************************/
    case SYS_semop:
      printf("semop(semid=%d, semops=%p, nsops=%d)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_semop*/

/***********************************************************************************/
    case SYS_semctl:
      printf("semctl(semid=%d, semnum=%d, cmd=0x%08x, arg=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi,
        executableHandle->regs.rdx,
        executableHandle->regs.r10);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_semctl*/

/***********************************************************************************/
    case SYS_shmdt:
      printf("shmdt(shmaddr=%p)\n",
        executableHandle->regs.rdi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_shmdt*/

/***********************************************************************************/
    case SYS_msgget:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // TODO: Get message returned.
      printf("msgget(key=%d, msgflags=0x%08x)\n",
        executableHandle->regs.rdi,
        executableHandle->regs.rsi);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_msgget*/

/***********************************************************************************/
    case SYS_msgsnd:
      printf("msgsnd(msqid=%d, msgptr=%p, msgsize=0x%08x, msgflags=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx,
              executableHandle->regs.r10);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_msgsnd*/

/***********************************************************************************/
    case SYS_msgrcv:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // TODO: Get the returned message
      printf("msgrcv(msqid=%d, msgptr=%p, msgsize=0x%08x, msgtyp=%d, msgflags=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx,
              executableHandle->regs.r10,
              executableHandle->regs.r8);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_msgrcv*/

/***********************************************************************************/
    case SYS_msgctl:
      printf("msgctl(msqid=%d, cmd=0x%08x, msgptr=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_msgctl*/

/***********************************************************************************/
    case SYS_fcntl:
      printf("fcntl(fd=%d, cmd=0x%08x, buff=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_fcntl*/

/***********************************************************************************/
    case SYS_flock:
      printf("flock(fd=%d, cmd=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_flock*/

/***********************************************************************************/
    case SYS_fsync:
      printf("fsync(fd=%d)\n",
              executableHandle->regs.rdi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_fsync*/

/***********************************************************************************/
    case SYS_fdatasync:
      printf("fdatasync(fd=%d)\n",
              executableHandle->regs.rdi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_fdatasync*/

/***********************************************************************************/
    case SYS_truncate:
      err = readStringFromProcessMemory(executableHandle->pid,
                                        tmpBuffer1,
                                        &tmpBuffer1);

      printf("truncate(path=\"%s\", size=0x%08x)\n",
              tmpBuffer1,
              executableHandle->regs.rsi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_truncate*/

/***********************************************************************************/
    case SYS_ftruncate:
      printf("ftruncate(fd=%d, size=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_ftruncate*/

/***********************************************************************************/
    case SYS_getdents:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      /* TODO: Can we read the directory entries?? */
      printf("getdents(fd=%d, dirents=%p, nentries=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getdents*/

/***********************************************************************************/
    case SYS_getcwd:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // TODO: Can we extract the returned directory name??
      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      printf("getcwd(buffer=%d, size=0x%08x)\n",
              tmpBuffer1,
              executableHandle->regs.rsi);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getcwd*/

/***********************************************************************************/
    case SYS_chdir:
      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      printf("chdir(path=%d)\n", tmpBuffer1);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_chdir*/

/***********************************************************************************/
    case SYS_fchdir:
      printf("fchdir(fd=%d)\n", executableHandle->regs.rdi);
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_mkdir*/

/***********************************************************************************/
    case SYS_rmdir:
      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);

      printf("rmdir(name=%d)\n", tmpBuffer1);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_symlink*/

/***********************************************************************************/
    case SYS_readlink:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
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
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_chmod*/

/***********************************************************************************/
    case SYS_fchmod:

      printf("fchmod(fd=%d, mode=0x%08x)\n",
             executableHandle->regs.rdi,
             executableHandle->regs.rsi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_chown*/

/***********************************************************************************/
    case SYS_fchown:
      printf("fchown(fd=%d, uid=0x%08x, gid=0x%08x)\n",
             executableHandle->regs.rdi,
             executableHandle->regs.rsi,
             executableHandle->regs.rdx);
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_fchown*/

/***********************************************************************************/
    case SYS_umask:
      printf("umask(mask=0x%08x)\n", executableHandle->regs.rdi);
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_umask*/

/***********************************************************************************/
    case SYS_gettimeofday:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // TODO: Get the data returned
      printf("gettimeofday()\n");
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_gettimeofday*/

/***********************************************************************************/
    case SYS_getrlimit:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // TODO: Get rlimit value
      printf("getrlimit(resource=0x%08x, rlimit=%p)\n",
             executableHandle->regs.rdi,
             executableHandle->regs.rsi);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getrlimit*/

/***********************************************************************************/
    case SYS_getrusage:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // TODO: Can we get returned data?
      printf("getrusage(who=%d)\n", executableHandle->regs.rdi);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getrusage*/

/***********************************************************************************/
    case SYS_sysinfo:
      //TODO: Does this retrieve sysdata?
      printf("sysinfo()\n");
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_sysinfo*/

/***********************************************************************************/
    case SYS_times:
      printf("times(tms-addr=%p)\n", executableHandle->regs.rdi);
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_times*/

/***********************************************************************************/
    case SYS_ptrace:
    {
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // Sometimes data will only be available at syscall exit.
      // TODO: Can we retrieve this data??
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
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_ptrace*/

    }

/***********************************************************************************/
    case SYS_getuid:
      printf("getuid()\n"); // Prints UID on return.
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getuid*/

/***********************************************************************************/
    case SYS_syslog:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      /*
       * TODO: We could get the contents of kernel buffer.
       * We would have to progress to the syscall exit.
       */
      printf("syslog(type=%d, buff=%p, size=0x%08x)\n",
             executableHandle->regs.rdi,
             executableHandle->regs.rsi,
             executableHandle->regs.rdx);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_syslog*/

/***********************************************************************************/
    case SYS_getgid:
      printf("getgid()\n"); // Prints GID on return.
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getgid*/

/***********************************************************************************/
    case SYS_setuid:
      printf("setuid(uid=%s)\n", executableHandle->regs.rdi);
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_setuid*/

/***********************************************************************************/
    case SYS_geteuid:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // TODO: Get euid
      printf("geteuid()\n");

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_geteuid*/

/***********************************************************************************/
    case SYS_getegid:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // TODO: Get egid
      printf("getegid()\n");

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getegid*/

/***********************************************************************************/
    case SYS_setpgid:
      printf("setpgid(pid=%s, pgid=%d)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_setpgid*/

/***********************************************************************************/
    case SYS_getppid:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // TOD: Get ppid
      printf("getppid()\n");
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getppid*/

/***********************************************************************************/
    case SYS_getpgrp:
      printf("getpgrp()\n");
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getpgrp*/

/***********************************************************************************/
    case SYS_setsid:
      printf("setsid()\n");
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_setsid*/

/***********************************************************************************/
    case SYS_setreuid:
      printf("setreuid(uid=%d, euid=%d)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_setreuid*/

/***********************************************************************************/
    case SYS_setregid:
      printf("setregid(gid=%d, egid=%d)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_setregid*/

/***********************************************************************************/
    case SYS_getgroups:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      //TODO: Get group data
      printf("getgroups(groupentsize=%d, groups-addr=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getgroups*/

/***********************************************************************************/
    case SYS_setgroups:
      printf("setgroups(groupentsize=%d, groups-addr=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_setgroups*/

/***********************************************************************************/
    case SYS_setresuid:
      printf("setresuid(ruid=%d, euid=%d, suid=%d)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_setresuid*/

/***********************************************************************************/
    case SYS_getresuid:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // TODO: Progress to syscall exit and receive the actual values.
      printf("getresuid(ruid=%p, euid=%p, suid=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getresuid*/

/***********************************************************************************/
    case SYS_setresgid:
      printf("setresgid(rgid=%d, egid=%d, sgid=%d)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_setresgid*/

/***********************************************************************************/
    case SYS_getresgid:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // TODO: Progress to syscall exit and receive the actual values.
      printf("getresgid(rgid=%p, egid=%p, sgid=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getresgid*/

/***********************************************************************************/
    case SYS_getpgid:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // TODO: Get pgid value
      printf("getpgid(pid=%d)\n",
              executableHandle->regs.rdi);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getpgid*/

/***********************************************************************************/
    case SYS_setfsuid:
      printf("setfsuid(uid=%d)\n",
              executableHandle->regs.rdi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_setfsuid*/

/***********************************************************************************/
    case SYS_setfsgid:
      printf("setfsgid(gid=%d)\n",
              executableHandle->regs.rdi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_setfsgid*/

/***********************************************************************************/
    case SYS_getsid:
      printf("getsid(pid=%d)\n",
              executableHandle->regs.rdi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getsid*/

/***********************************************************************************/
    case SYS_capget:
      // TODO: Look into what data we can get from capget/capset
      printf("capget()\n");
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_capget*/

/***********************************************************************************/
    case SYS_capset:
      printf("capset()\n");
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_capset*/

/***********************************************************************************/
    case SYS_rt_sigpending:
      printf("rt_sigpending(set=%p, sigentsize=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_rt_sigpending*/

/***********************************************************************************/
    case SYS_rt_sigtimedwait:
      printf("rt_sigtimedwait(*uthese=%p, uinfo=%p, *uts=%p, sigentsize=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx,
              executableHandle->regs.r10);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_rt_sigtimedwait*/

/***********************************************************************************/
    case SYS_rt_sigqueueinfo:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      printf("rt_sigqueueinfo(pid=%d, sig=0x%08x, *uinfo=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_rt_sigqueueinfo*/

/***********************************************************************************/
    case SYS_rt_sigsuspend:
      printf("rt_sigsuspend(*newset=%p, sigentsize=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_rt_sigsuspend*/
/***********************************************************************************/
    case SYS_sigaltstack:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      // TODO we could receive the signal stack at the syscall exit.
      printf("sigaltstack(*uss=%p, *uoss=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_utime*/

/***********************************************************************************/
    case SYS_mknod:
      printf("mknod(filename=%s, mode=0x%08x, dev=%d)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_mknod*/

/***********************************************************************************/
    case SYS_personality:
      printf("personality(personality=0x%08x)\n",
              executableHandle->regs.rdi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_personality*/

/***********************************************************************************/
    case SYS_ustat:
      printf("ustat(dev=%d)\n", executableHandle->regs.rdi); // This function is deprecated

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_ustat*/

/***********************************************************************************/
    case SYS_statfs:
      // TODO: Could we grab the stat struct data
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

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

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_statfs*/

/***********************************************************************************/
    case SYS_fstatfs:
      printf("fstatfs(fd=%d)\n", executableHandle->regs.rdi); // This function is deprecated

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_sysfs*/

/***********************************************************************************/
    case SYS_getpriority:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      printf("getpriority(which=%d, who=%d)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getpriority*/

/***********************************************************************************/
    case SYS_setpriority:
      printf("setpriority(which=%d, who=%d, priority=%d)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_setpriority*/

/***********************************************************************************/
    case SYS_sched_setparam:
      printf("sched_setparam(pid=%d, param-struct=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_sched_setparam*/

/***********************************************************************************/
    case SYS_sched_getparam:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      printf("sched_getparam(pid=%d, param-struct=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_sched_getparam*/

/***********************************************************************************/
    case SYS_sched_setscheduler:
      printf("sched_setscheduler(pid=%d, policy=%d, param-struct=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_sched_setscheduler*/

/***********************************************************************************/
    case SYS_sched_getscheduler:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      printf("sched_getscheduler(pid=%d)\n",
              executableHandle->regs.rdi);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_sched_getscheduler*/

/***********************************************************************************/
    case SYS_sched_get_priority_max:
      printf("sched_get_priority_max(policy=%d)\n",
              executableHandle->regs.rdi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_sched_get_priority_max*/

/***********************************************************************************/
    case SYS_sched_get_priority_min:
      printf("sched_get_priority_min(policy=%d)\n",
              executableHandle->regs.rdi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
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

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_sched_rr_get_interval*/

    case SYS_mlock:
      printf("mlock(start=0x%08x, length=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_mlock*/

/***********************************************************************************/
    case SYS_munlock:
      printf("munlock(start=0x%08x, length=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi);
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_munlock*/

/***********************************************************************************/
    case SYS_mlockall:
      printf("mlockall(flags=0x%08x)\n",
              executableHandle->regs.rdi);
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_mlockall*/

/***********************************************************************************/
    case SYS_munlockall:
      printf("munlockall()\n");
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_munlockall*/
/***********************************************************************************/
    case SYS_vhangup:
      printf("vhangup()\n");
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);

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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);

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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);

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

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);

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

/***********************************************************************************/
    case SYS_io_submit:
      uint64_t address = 0;

      err = readProcessMemoryFromPID(executableHandle->pid, executableHandle->regs.rdx, &address, sizeof(uint64_t));
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("io_submit(context=0x%016x, nr=%ld, iocb-addr=%p\n)",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              address);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_io_submit*/

/***********************************************************************************/
    case SYS_io_cancel:
      printf("io_cancel(context-ID=0x%016x, iocb-struct-addr=%p, result-addr=%p\n)",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_io_cancel*/

/***********************************************************************************/
    case SYS_lookup_dcookie:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readProcessMemoryFromPID(executableHandle->pid, executableHandle->regs.rsi, tmpBuffer1, sizeof(uint64_t));
      if(err != ERR_NONE)
      {
        return err;
      }
      printf("lookup_dcookie(cookie=0x%016x, buffer=\"%s\", length=%d\n)",
              executableHandle->regs.rdi,
              tmpBuffer1,
              executableHandle->regs.rdx);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_lookup_dcookie*/

/***********************************************************************************/
    case SYS_epoll_create:
      printf("epoll_create(length=%d\n)",
              executableHandle->regs.rdi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_epoll_create*/

/***********************************************************************************/
    case SYS_remap_file_pages:
      printf("remap_file_pages(virtual-addr=%p, size=0x%08x, protections=size=0x%016x" \
             "page-offset=size=0x%016x, flags=size=0x%08x\n)",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx,
              executableHandle->regs.r10,
              executableHandle->regs.r8);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_remap_file_pages*/

/***********************************************************************************/
    case SYS_getdents64:
      struct linux_dirent d = {0};

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.rsi,
                                     &d,
                                     sizeof(struct linux_dirent));
      if(err != ERR_NONE)
      {
        return err;
      }
      printf("getdents64(fd=%u, dir_Inode=%u, dir_offset=0x%08x, dirent-length=%lu, dir-name=\"%s\", count=%lu)\n",
              executableHandle->regs.rdi,
              d.d_ino,
              d.d_off,
              d.d_reclen,
              d.d_name);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_getdents64*/

/***********************************************************************************/
    case SYS_set_tid_address:
      int tid = 0;

      err = readProcessMemoryFromPID(executableHandle->pid, executableHandle->regs.rdi, &tid, sizeof(int));
      printf("set_tid_address(tid=%u\n)", tid);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_set_tid_address*/

/***********************************************************************************/
    case SYS_restart_syscall:
      printf("restart_syscall()\n");
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_restart_syscall*/

  /***********************************************************************************/
    case SYS_semtimedop:
      struct sembuf sBuff = {0};

      if(executableHandle->regs.rdx == 0) // There are no sembuf structures
      {
        printf("semtimedop(semid=%d, no-ops)\n",
                executableHandle->regs.rdi);
        break;
      }

      tmpBuffer1 = (struct sembuf *) malloc(executableHandle->regs.rdx * sizeof(struct sembuf));
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      printf("semtimedop(semid=%d, ",
              executableHandle->regs.rdi);
      for(int i = 0; i < executableHandle->regs.rdx; i++)
      {
        err = readProcessMemoryFromPID(executableHandle->pid,
                                       executableHandle->regs.rsi + (i * sizeof(struct sembuf)),
                                       &sBuff,
                                       sizeof(struct sembuf));

        printf("sembuf: %d", i+1);
        if(i == executableHandle->regs.rdx - 1)
        {
          printf("sem-num=%d, sem-op=0x%04x, sem-flag=0x%04x, ",
                  sBuff.sem_num,
                  sBuff.sem_op,
                  sBuff.sem_flg);
        }
        else
        {
          printf("sem-num=%d, sem-op=0x%04x, sem-flag=0x%04x\n\n",
                  sBuff.sem_num,
                  sBuff.sem_op,
                  sBuff.sem_flg);
        }
      }
      printf("nsops=%d)\n", executableHandle->regs.rdx);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_semtimedop*/

/***********************************************************************************/
    case SYS_fadvise64:

      switch(executableHandle->regs.r10)
      {
        case POSIX_FADV_NORMAL:
          printf("fadvise64(fd=%d, offset=0x%08x, length=0x%08x, advice= POSIX_FADV_NORMAL\n)",
                  executableHandle->regs.rdi,
                  executableHandle->regs.rsi,
                  executableHandle->regs.rdx);
          break;

        case POSIX_FADV_SEQUENTIAL:
          printf("fadvise64(fd=%d, offset=0x%08x, length=0x%08x, advice= POSIX_FADV_SEQUENTIAL\n)",
                  executableHandle->regs.rdi,
                  executableHandle->regs.rsi,
                  executableHandle->regs.rdx);
          break;

        case POSIX_FADV_RANDOM:
          printf("fadvise64(fd=%d, offset=0x%08x, length=0x%08x, advice= POSIX_FADV_RANDOM\n)",
                  executableHandle->regs.rdi,
                  executableHandle->regs.rsi,
                  executableHandle->regs.rdx);
          break;

        case POSIX_FADV_NOREUSE:
          printf("fadvise64(fd=%d, offset=0x%08x, length=0x%08x, advice= POSIX_FADV_NOREUSE\n)",
                  executableHandle->regs.rdi,
                  executableHandle->regs.rsi,
                  executableHandle->regs.rdx);
          break;

        case POSIX_FADV_WILLNEED:
          printf("fadvise64(fd=%d, offset=0x%08x, length=0x%08x, advice= POSIX_FADV_WILLNEED\n)",
                  executableHandle->regs.rdi,
                  executableHandle->regs.rsi,
                  executableHandle->regs.rdx);
          break;

        case POSIX_FADV_DONTNEED:
          printf("fadvise64(fd=%d, offset=0x%08x, length=0x%08x, advice= POSIX_FADV_DONTNEED\n)",
                  executableHandle->regs.rdi,
                  executableHandle->regs.rsi,
                  executableHandle->regs.rdx);
          break;
      }

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_fadvise64*/

/***********************************************************************************/
    case SYS_timer_create:
      char clockID[50] = {0};
      timer_t time = 0;
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      /* Get clockid argument in human readable format. */
      switch(executableHandle->regs.rdi)
      {
        case CLOCK_REALTIME:
          strcpy(clockID, "CLOCK_REALTIME");
          break;

        case CLOCK_MONOTONIC:
          strcpy(clockID, "CLOCK_MONOTONIC");
          break;

        case CLOCK_PROCESS_CPUTIME_ID:
          strcpy(clockID, "CLOCK_PROCESS_CPUTIME_ID");
          break;

        case CLOCK_THREAD_CPUTIME_ID:
          strcpy(clockID, "CLOCK_THREAD_CPUTIME_ID");
          break;

        case CLOCK_BOOTTIME:
          strcpy(clockID, "CLOCK_BOOTTIME");
          break;

        case CLOCK_REALTIME_ALARM:
          strcpy(clockID, "CLOCK_REALTIME_ALARM");
          break;

        case CLOCK_BOOTTIME_ALARM:
          strcpy(clockID, "CLOCK_BOOTTIME_ALARM");
          break;

        case CLOCK_TAI:
          strcpy(clockID, "CLOCK_TAI");
          break;
      }

      err = readProcessMemoryFromPID(executableHandle->pid, executableHandle->regs.rdx, &time, sizeof(timer_t));
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("timer_create(clockID\"%s\", sevp-addr=%p, timerID=%d)\n", clockID, executableHandle->regs.rsi, time);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_timer_create*/

/***********************************************************************************/
    case SYS_timer_settime:
      struct itimerspec oldTime = {0};
      struct itimerspec newTime = {0};

      err= readProcessMemoryFromPID(executableHandle->pid, executableHandle->regs.rdx, &newTime, sizeof(struct itimerspec));
      if(err != ERR_NONE)
      {
        return err;
      }

      err= readProcessMemoryFromPID(executableHandle->pid, executableHandle->regs.r10, &oldTime, sizeof(struct itimerspec));
      if(err != ERR_NONE)
      {
        return err;
      }


      printf("timer_settime(timerID=%d, flags=0x%08x, newtime-interval=%d, newtime-value=%d", \
             "oldtime-interval=%d, oldtime-value=%d\n)",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              newTime.it_interval,
              newTime.it_value,
              oldTime.it_interval,
              oldTime.it_value);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_timer_settime*/

/***********************************************************************************/
    case SYS_timer_gettime:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      struct itimerspec Time = {0};

      err= readProcessMemoryFromPID(executableHandle->pid, executableHandle->regs.rdi, &Time, sizeof(struct itimerspec));
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("timer_gettime(timerID=%d, flags=0x%08x, time-interval=%d, time-value=%d\n)",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              Time.it_interval,
              Time.it_value);

      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_timer_gettime*/

/***********************************************************************************/
    case SYS_timer_getoverrun:
      printf("timer_getoverrun(timerID=%d)\n", executableHandle->regs.rdi);
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\t(overrun-time)\n\n", executableHandle->regs.rax);
      break; /*SYS_timer_getoverrun*/

/***********************************************************************************/
    case SYS_timer_delete:
      printf("timer_delete(timerID=%d)\n", executableHandle->regs.rdi);
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_timer_delete*/

/***********************************************************************************/
    case SYS_clock_settime:
      struct timespec ts1 = {0};
      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.rsi,
                                     &ts1,
                                     sizeof(struct timespec));
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("clock_settime(timerID=%d, seconds=%d, nano-seconds=%d)\n",
              executableHandle->regs.rdi,
              ts1.tv_sec,
              ts1.tv_nsec);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_clock_settime*/

/***********************************************************************************/
    case SYS_clock_gettime:
      struct timespec ts2 = {0};

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.rsi,
                                     &ts2,
                                     sizeof(struct timespec));
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("clock_gettime(timerID=%d, seconds=%d, nano-seconds=%d)\n",
              executableHandle->regs.rdi,
              ts2.tv_sec,
              ts2.tv_nsec);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_clock_gettime*/

/***********************************************************************************/
    case SYS_clock_getres:
      struct timespec ts3 = {0};

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.rsi,
                                     &ts3,
                                     sizeof(struct timespec));
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("clock_getres(timerID=%d, seconds=%d, nano-seconds=%d)\n",
              executableHandle->regs.rdi,
              ts3.tv_sec,
              ts3.tv_nsec);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_clock_getres*/

/***********************************************************************************/
    case SYS_clock_nanosleep:
      struct timespec req1 = {0};
      struct timespec remain1 = {0};


      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.rsi,
                                     &req1,
                                     sizeof(struct timespec));
      if(err != ERR_NONE)
      {
        return err;
      }

      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.rsi,
                                     &remain1,
                                     sizeof(struct timespec));
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("clock_nanosleep(timerID=%d, seconds=%d, nano-seconds=%d)\n",
              executableHandle->regs.rdi,
              req1.tv_sec,
              req1.tv_nsec,
              remain1.tv_sec, // TODO: This may be NULL (will this matter?)
              remain1.tv_nsec);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\n\n", executableHandle->regs.rax);
      break; /*SYS_clock_nanosleep*/

/***********************************************************************************/
    case SYS_exit_group:
      printf("exit_group(errror-code=%d)\n", executableHandle->regs.rdi);
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d\t(overrun-time)\n\n", executableHandle->regs.rax);
      break; /*SYS_exit_group*/

/***********************************************************************************/
    case SYS_epoll_wait:
      struct epoll_event events1 = {0};
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      err = readProcessMemoryFromPID(executableHandle->pid, executableHandle->regs.rdi,
                                     &events1,
                                     sizeof(struct epoll_event));
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("epoll_wait(epfd=%d, epoll-event=0x%08x, max-events=%d, timeout=%d)\n",
              executableHandle->regs.rdi,
              events1.events,
              executableHandle->regs.rsi,
              executableHandle->regs.r10);
      printf("Returned With: %d)\n\n", executableHandle->regs.rax);
      break; /*SYS_epoll_wait*/

/***********************************************************************************/
    case SYS_epoll_ctl:
      struct epoll_event events2 = {0};
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      err = readProcessMemoryFromPID(executableHandle->pid, executableHandle->regs.r10,
                                     &events2,
                                     sizeof(struct epoll_event));
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("epoll_ctl(epfd=%d, op=0x%08x, fd=%d, epoll-event=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx,
              events2.events
            );
      printf("Returned With: %d)\n\n", executableHandle->regs.rax);
      break; /*SYS_epoll_ctl*/

/***********************************************************************************/
    case SYS_tgkill:
      printf("tgkill(tgid=%d, pid=%d, signal=0x%08x, timeout=%d)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx);
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d)\n\n", executableHandle->regs.rax);
      break; /*SYS_tgkill*/

/***********************************************************************************/
    case SYS_utimes:
      struct utimbuf utimeBuff = {0};

      // Read in filename
      tmpBuffer1 = malloc(PATH_MAX);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      // Read in time buffer
      err = readProcessMemoryFromPID(executableHandle->pid, executableHandle->regs.rsi,
                                     &utimeBuff,
                                     sizeof(struct utimbuf));
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("utimes(filename=\"%s\", access-time=%d, modification-time=%d)\n",
              tmpBuffer1,
              utimeBuff.actime,
              utimeBuff.modtime);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d)\n\n", executableHandle->regs.rax);
      break; /*SYS_utimes*/

/***********************************************************************************/
    case SYS_mbind:
      uint64_t nmask1 = 0;

      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.r10,
                                     &nmask1,
                                     sizeof(uint64_t));
      if(err != ERR_NONE)
      {
        return err;
      }
      /* TODO: Could we print the mode flags as there macro names?*/
      printf("mbind(start=%ld, length=%ld, mode=0x%08x, nmask=0x%016x, max-node=%ld, flags=0x%08x)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx,
              nmask1,
              executableHandle->regs.r8,
              executableHandle->regs.r9);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d)\n\n", executableHandle->regs.rax);
      break; /*SYS_mbind*/

/***********************************************************************************/
    case SYS_set_mempolicy:
      uint64_t nmask2 = 0;

      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.rsi,
                                     &nmask2,
                                     sizeof(uint64_t));
      if(err != ERR_NONE)
      {
        return err;
      }
      /* TODO: Could we print the mode flags as there macro names?*/
      printf("set_mempolicy(mode=0x%08x, nmask=0x%016x, max-node=%ld)\n",
              executableHandle->regs.rdi,
              nmask2,
              executableHandle->regs.r10);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d)\n\n", executableHandle->regs.rax);
      break; /*SYS_set_mempolicy*/

/***********************************************************************************/
    case SYS_get_mempolicy:
      unsigned long mode = 0;

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      /* TODO: Could we print the mode flags as there macro names?*/
      printf("get_mempolicy(mode=0x%08x, nmask=0x%016x, max-node=%ld)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              executableHandle->regs.r10);

      printf("Returned With: %d)\n\n", executableHandle->regs.rax);
      break; /*SYS_get_mempolicy*/

/***********************************************************************************/
    case SYS_mq_open:
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

      printf("mq_open(filename=\"tmpBuffer1\", oflags=0x%08x)\n",
              tmpBuffer1,
              executableHandle->regs.rsi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d)\n\n", executableHandle->regs.rax);
      break; /*SYS_mq_open*/

/***********************************************************************************/
    case SYS_mq_unlink:
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

      printf("mq_unlink(filename=\"tmpBuffer1\")\n", tmpBuffer1);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d)\n\n", executableHandle->regs.rax);
      break; /*SYS_mq_unlink*/

/***********************************************************************************/
    case SYS_mq_timedsend:
      struct timespec tSpec = {0};
      tmpBuffer1 = malloc(executableHandle->regs.rdx);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      // Get the message
      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.rsi,
                                     tmpBuffer1,
                                     executableHandle->regs.rdx);
      if(err != ERR_NONE)
      {
        return err;
      }

      // Get the timespec struct
      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.r8,
                                     &tSpec,
                                     sizeof(struct timespec));
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("mq_timedsend(mqdes=%d, message=\"tmpBuffer1\", msg-length=0x%08x," \
             " msg-priority=%d, seconds=%d, nano-seconds=%d)\n",
                           executableHandle->regs.rdi,
                           tmpBuffer1,
                           executableHandle->regs.rdx,
                           executableHandle->regs.r10,
                           tSpec.tv_sec,
                           tSpec.tv_nsec);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d)\n\n", executableHandle->regs.rax);
      break; /*SYS_mq_timedsend*/

/***********************************************************************************/
    case SYS_mq_timedreceive:
      struct timespec tSpec1 = {0};
      unsigned int msg_pri = 0;
      tmpBuffer1 = malloc(executableHandle->regs.rdx);
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      // Get the messager priority
      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.r10,
                                     &msg_pri,
                                     sizeof(unsigned int));
      if(err != ERR_NONE)
      {
        return err;
      }

      // Get the timespec struct
      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.r8,
                                     &tSpec1,
                                     sizeof(struct timespec));
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("mq_timedreceive(mqdes=%d, message=\"THE MESSAGE IS UNAVAILABLE\", msg-length=0x%08x," \
             " msg-priority=%d, seconds=%d, nano-seconds=%d)\n",
                           executableHandle->regs.rdi,
                           tmpBuffer1,
                           executableHandle->regs.rdx,
                           executableHandle->regs.r10,
                           tSpec1.tv_sec,
                           tSpec1.tv_nsec);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d)\n\n", executableHandle->regs.rax);
      break; /*SYS_mq_timedreceive*/

/***********************************************************************************/
    case SYS_mq_notify:
      /* NOTE: We could maybe grab sigEvent details but we only print the pointer for
       * the sake of simplicity, printing the details of a sigevent would
       * warrant its own function.
      */
      printf("mq_notify(mqdes=%d, sigEvent-addr=%p)\n",
                        executableHandle->regs.rdi,
                        executableHandle->regs.rsi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d)\n\n", executableHandle->regs.rax);
      break; /*SYS_mq_notify*/

/***********************************************************************************/
    case SYS_mq_getsetattr:
      /*
       * NOTE: The documentation for this syscall is sparse: https://man7.org/linux/man-pages/man2/mq_getsetattr.2.html
       * I do not know how we could tell the difference between get/set attr.
      */
      printf("mq_getsetattr(mqdes=%d, attr-addr=%p)\n",
                        executableHandle->regs.rdi,
                        executableHandle->regs.rsi);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d)\n\n", executableHandle->regs.rax);
      break; /*SYS_mq_getsetattr*/

/***********************************************************************************/
    case SYS_kexec_load:
      struct kexec_segment execLoadSegments = {0};

      // The kernel puts a limit of 16 for nrSegments
      for(int i = 0; i < executableHandle->regs.rsi && i < 16; i++)
      {
        err = readProcessMemoryFromPID(executableHandle->pid,
                                      executableHandle->regs.rdx + i * sizeof(struct kexec_segment),
                                      &execLoadSegments,
                                      sizeof(struct kexec_segment));
        if(err != ERR_NONE)
        {
          return err;
        }

        printf("kexec_load(entry=0x%016x, nrSegments=0x%016x, kexec_segment->buf=%p, " \
                          "kexec_segment->bufsz=0x%016x, kexec_segment->physicalAddr=%p, " \
                          "kexec_segment->memsz=0x%016x, flags=0x%08x)\n",
                          executableHandle->regs.rdi,
                          executableHandle->regs.rsi,
                          execLoadSegments.buf,
                          execLoadSegments.bufsz,
                          execLoadSegments.mem,
                          execLoadSegments.memsz,
                          executableHandle->regs.r10);

      }

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d)\n\n", executableHandle->regs.rax);
      break; /*SYS_kexec_load*/

/***********************************************************************************/
    case SYS_waitid:
      siginfo_t sInfo = {0};
      struct rusage resUsage = {0};

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      err = readProcessMemoryFromPID(executableHandle->pid,
                                     executableHandle->regs.rdx,
                                     &sInfo,
                                     sizeof(siginfo_t));

      if(err != ERR_NONE)
      {
        return err;
      }

      /*
       * NOTE: I've decided not print the rusage struct,
       * as there are many member fields. This would make the printf
       * statement messy.
      */

      printf("waitid(which=%d, pid=%d, siginfo->si_signo=%d, " \
             "siginfo->si_errno=%d, siginfo->si_code=%d, siginfo->si_value=%d, " \
             "options=0x%08x, rusage-addr=%p)\n",
              executableHandle->regs.rdi,
              executableHandle->regs.rsi,
              sInfo.si_signo,
              sInfo.si_errno,
              sInfo.si_code,
              sInfo.si_value,
              executableHandle->regs.r10,
              executableHandle->regs.r8);

      printf("Returned With: %d)\n\n", executableHandle->regs.rax);
      break; /*SYS_waitid*/

/***********************************************************************************/
    case SYS_add_key:
      // Allocate buffer for type parameter
      tmpBuffer1 = malloc(512); // Arbitrary length (512 should be more than enough).
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      // Allocate buffer for description. The documentation does not mention a limit
      // to the size of description.
      tmpBuffer2 = malloc(4096);
      if(tmpBuffer2 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      // Allocate buffer for 'payload' parameter, only if psize > 0
      if(executableHandle->regs.r10 > 0)
      {
        tmpBuffer3 = malloc(executableHandle->regs.r10);
        if(tmpBuffer3 == NULL)
        {
          return ERR_MEMORY_ALLOCATION_FAILED;
        }

        err = readProcessMemoryFromPID(executableHandle->pid,
                                       executableHandle->regs.rdx,
                                       tmpBuffer3,
                                       executableHandle->regs.r10);

        if(err != ERR_NONE)
        {
          return err;
        }
      }

      // Read 'description' parameter.
      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rsi,
                                        &tmpBuffer2);
      if(err != ERR_NONE)
      {
        return err;
      }

      // Read 'type' parameter.
      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("add_key(type=\"%s\", description=\"%s\", payload=\"%s\", " \
             "plen=%d, destringid=0x%08x)\n",
              tmpBuffer1,
              tmpBuffer2,
              tmpBuffer3,
              executableHandle->regs.r10,
              executableHandle->regs.r8);

      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);
      printf("Returned With: %d)\n\n", executableHandle->regs.rax);
      break; /*SYS_add_key*/

/***********************************************************************************/
    case SYS_request_key:
      /*
       * NOTE: The callout argument (third parameter) only seems to be checked whether or not
       * it is NULL. Given this, I have chosen to only print NULL/NOT-NULL
      */
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      // Allocate buffer for type parameter
      tmpBuffer1 = malloc(512); // Arbitrary length (512 should be more than enough).
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      // Allocate buffer for description. The documentation does not mention a limit
      // to the size of description.
      tmpBuffer2 = malloc(4096);
      if(tmpBuffer2 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      // Read 'description' parameter.
      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rsi,
                                        &tmpBuffer2);
      if(err != ERR_NONE)
      {
        return err;
      }

      // Read 'type' parameter.
      err = readStringFromProcessMemory(executableHandle->pid,
                                        executableHandle->regs.rdi,
                                        &tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      if(executableHandle->regs.rdx == NULL)
      {
        printf("request_key(type=\"%s\", description=\"%s\", callout_info=NULL, dest_keyring=0x%08x)\n",
                tmpBuffer1,
                tmpBuffer2,
                executableHandle->regs.r10);
      }
      else
      {
        printf("request_key(type=\"%s\", description=\"%s\", callout_info=NOT-NULL, dest_keyring=0x%08x)\n",
                tmpBuffer1,
                tmpBuffer2,
                executableHandle->regs.r10);
      }

      printf("Returned With: %d)\n\n", executableHandle->regs.rax);
      break; /*SYS_request_key*/

/***********************************************************************************/
    case SYS_keyctl:
      PROGRESS_TO_SYSCALL_EXIT(executableHandle->pid);

      tmpBuffer1 = malloc(30); // None of the strings that are copied are longer than 27.
      if(tmpBuffer1 == NULL)
      {
        return ERR_MEMORY_ALLOCATION_FAILED;
      }

      err = getKeyctlOperation(executableHandle->regs.rdi, tmpBuffer1);
      if(err != ERR_NONE)
      {
        return err;
      }

      printf("keyctl(cmd=%s, arg1=0x%08x, arg2=0x%08x, arg3=0x%08x, arg4=0x%08x,)\n",
              tmpBuffer1,
              executableHandle->regs.rsi,
              executableHandle->regs.rdx,
              executableHandle->regs.r10,
              executableHandle->regs.r8);

      printf("Returned With: %d)\n\n", executableHandle->regs.rax);
      break; /*SYS_keyctl*/










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
      if(ptrace(PTRACE_GETREGS, executableHandle->pid,
                NULL, &executableHandle->regs) < 0)
      {
        return ERR_PROCESS_OPERATION_FAILED;
      }

      if(isRepeatedSyscallX64(&executableHandle->regs, &oldRegisters) == FALSE)
      {
        printf("Entering sycall number: %d\n", executableHandle->regs.orig_rax);
        printSyscallInfoElf64(executableHandle, firstSysCall);
        firstSysCall = FALSE;
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

static void unittest_getKeyctlOperation_validOperations()
{
  char buff[40] = {0};
  int8_t err = ERR_NONE;

  err = getKeyctlOperation(KEYCTL_GET_KEYRING_ID, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_GET_KEYRING_ID") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_JOIN_SESSION_KEYRING, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_JOIN_SESSION_KEYRING") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_UPDATE, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_UPDATE") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_REVOKE, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_REVOKE") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_CHOWN, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_CHOWN") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_SETPERM, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_SETPERM") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_DESCRIBE, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_DESCRIBE") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_CLEAR, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_CLEAR") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_LINK, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_LINK") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_UNLINK, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_UNLINK") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_SEARCH, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_SEARCH") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_READ, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_READ") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_INSTANTIATE, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_INSTANTIATE") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_NEGATE, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_NEGATE") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_SET_REQKEY_KEYRING, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_SET_REQKEY_KEYRING") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_SET_TIMEOUT, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_SET_TIMEOUT") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_ASSUME_AUTHORITY, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_ASSUME_AUTHORITY") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_GET_SECURITY, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_GET_SECURITY") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_SESSION_TO_PARENT, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_SESSION_TO_PARENT") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_REJECT, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_REJECT") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_INSTANTIATE_IOV, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_INSTANTIATE_IOV") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_INVALIDATE, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_INVALIDATE") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_GET_PERSISTENT, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_GET_PERSISTENT") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_DH_COMPUTE, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_DH_COMPUTE") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_PKEY_QUERY, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_PKEY_QUERY") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_PKEY_ENCRYPT, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_PKEY_ENCRYPT") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_PKEY_DECRYPT, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_PKEY_DECRYPT") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_PKEY_SIGN, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_PKEY_SIGN") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_PKEY_VERIFY, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_PKEY_VERIFY") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_RESTRICT_KEYRING, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_RESTRICT_KEYRING") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_MOVE, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_MOVE") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_CAPABILITIES, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_CAPABILITIES") == 0);

  memset(buff, '\0', sizeof(buff));
  err = getKeyctlOperation(KEYCTL_WATCH_KEY, buff);
  assert(err == ERR_NONE);
  assert(strcmp(buff, "KEYCTL_WATCH_KEY") == 0);
}

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
  unittest_getKeyctlOperation_validOperations(); // TODO: Confirm this test works.

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