/*
 *   Copyright (c) [2023], Calum Dawson
 *   All rights reserved.
 *   This code is the exclusive property of Calum Dawson.
 *   Any unauthorized use or reproduction without the explicit
 *   permission of Calum Dawson is strictly prohibited.
 *   Unauthorized copying of this file, via any medium, is
 *   strictly prohibited.
 *   Proprietary and confidential.
 *   Written by Calum Dawson calumjamesdawson@gmail.com, [2024].
 */

#ifndef _IOCS_
#define _IOCS_

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/queue.h>

#include "../../FileOperations/fileOps.h"
#include "../../Types/turtle_types.h"
#include "../../Memory/tvector.h"
#include "../IO/io.h"

typedef struct RunningProcess
{
  char     name   [256];                   // Filename of the executable.

  // uint16_t groups [20];                    // Supplementary group list
  uint16_t uMask;                          // File mode creation mask.

  char     speculationStoreBypass    [40]; // Speculative store bypass mitigation status.
  char     speculationIndirectBranch [40]; // Indirect branch speculation mode.
  char     signalQueue[20];                // Max. number for queue.

  char     state;               // state (R is running, S is sleeping, D is sleeping in an
                                // uninterruptible wait, Z is zombie, T is traced or stopped).
  
  uint32_t tgid;                // Thread group ID.
  uint32_t ngid;                // NUMA group ID (0 if none).

  pid_t    PID;                 // Process ID.
  pid_t    PPID;                // Parent process ID.
  pid_t    tracerPID;           // PID of process tracing this process (0 if not, or the tracer
                                // is outside of the current pid namespace).
  
  uint16_t uid;                 // Real, effective, saved set, and file system UIDs.                           
  uint16_t gid;                 // Real, effective, saved set, and file system GIDs.
  uint16_t fileDescriptorSize;  // number of file descriptor slots currently allocated.
  
  BOOL     kThread;    // Kernel thread flag, 1 is yes, 0 is no.

  uint64_t vmPeak;     // Peak virtual memory size.
  uint64_t vmSize;     // Total program size.
  uint64_t vmLock;     // Locked memory size
  uint64_t vmPin;      // Pinned memory size.
  uint64_t vmHWM;      // Peak resident set size ("high water mark")
  uint64_t vmRSS;      // Size of memory portions. It contains the three following parts
                       // (VmRSS = RssAnon + RssFile + RssShmem).
  uint64_t rssAnon;    // Size of resident anonymous memory.
  uint64_t rssFile;    // Size of resident file mappings.
  uint64_t rssShmem;   // Size of resident shmem memory (includes SysV shm, mapping of
                       // tmpfs and shared anonymous mappings).

  uint64_t vmData;     // Size of private data segments.
  uint64_t vmStack;    // Size of stack segments.
  uint64_t vmExe;      // Size of text segment.
  uint64_t vmLib;      // Size of shared library code
  uint64_t vmPTE;      // Size of page table entries
  uint64_t vmSwap;     // amount of swap used by anonymous private data
                       // (shmem swap usage is not included).

  uint64_t hugetLbPages;                    // Size of hugetlb memory portions
  uint8_t  coreDumping;                     // process's memory is currently being dumped
                                            // (killing the process may lead to a corrupted core).
  uint8_t  thpEnabled;                      // process is allowed to use THP (returns 0 when
                                            // PR_SET_THP_DISABLE is set on the process.
  uint16_t threads;                         // Number of threads owned by process.
  uint32_t threadSignalsPendingMask;        // bitmap of pending signals for the thread.
  uint32_t processSignalsPendingMask;       // bitmap of shared pending signals for the process.
  uint32_t blockedSignalsMask;              // bitmap of blocked signals.
  uint32_t ignoredSignalsMask;              // bitmap of ignored signals.
  uint32_t caughtSignalsMask;               // bitmap of caught signals.

  uint32_t InheritablecapabilitiesMask;     // bitmap of inheritable capabilities.
  uint32_t permittedCapabilitiesMask;       // bitmap of permitted capabilities.
  uint32_t effectiveCapabilitiesMask;       // bitmap of effective capabilities.
  uint32_t boundingCapabilitiesMask;        // bitmap of capabilities bounding set.
  uint32_t ambientCapabilitiesMask;         // bitmap of ambient capabilities.

  uint32_t noNewPrivs;                      // no_new_privs, like prctl(PR_GET_NO_NEW_PRIV, ...).
  uint32_t secComp;                         // seccomp mode, like prctl(PR_GET_SECCOMP, ...).

  uint16_t voluntaryContextSwitches;        // Number of voluntary context switches.
  uint16_t involuntaryContextSwitches;      // Involuntary number of context switches.

  uint64_t stackStartAddr;
  uint64_t stackLen;
  uint64_t heapStartAddr;
  uint64_t heapLen;
} TRunningProcess;


/*
 * A function to read all the running processes on a
 * Unix system, returning them in a TVector structure.
 * 
 * PARAM-1: An uninitialised TVector structure pointer.
 * 
 * RETURN: Returns an ERROR/WARNING code indicating the
 *         successfulness of reading the running processes.
*/
int16_t retrieveRunningProcessesData(TVector * vector);

void printAllProcessStatus(TVector * vector);
#endif