#include "./IOCs.h"

/*
 * A simmple helper function to help progress the character pointer on a given line
 * provided from the processes /proc/[PID]/status file.
*/
static char * progressPointerToData(char * pChar)
{
  if(pChar == NULL)
  {
    return NULL;
  }
  
  while(*pChar == ' ' || *pChar == ':' || *pChar == '\t')
  {
    ++pChar;
  }
  return pChar;
}

/*
 * Retrieve all information that will be usefull in determining any
 * IOC's of a process possibly indicated in the /proc/[PID]/status file.
*/
static uint8_t retrieveRunningProcessData(TRunningProcess * process)
{
  FILE * fileHandle = NULL;
  char line[400]    = {0};
  char path[20]     = {0};
  char tmpBuff[20]  = {0};
  uint16_t tgid     =  0;
  uint8_t err       = ERR_NONE;

  snprintf(path, 40, "/proc/%ld/status", process->PID);

  fileHandle = fopen(path, "r");
  if(fileHandle == NULL)
  {
    printf("Try Running With sudo As Certain Processes Require Root Priviledges.\n");
    return ERR_FILE_OPERATION_FAILED;
  }

  printf("---------------------------------------------------------------------------------\n");
  while(fgets(line, 400, fileHandle))
  {
    uint64_t tmpValue = 0;
    char tmpBuffer[16];
    char * pChar = NULL;

    
    if(strncmp(line, "Name", 4) == 0)
    {
      pChar = &line[4];
      pChar = progressPointerToData(pChar);

      strcpy(process->name, pChar);
      printf("Process Name:                        %s\n", process->name);
      printf("Process PID:                         %10u\n", process->PID);
    }

    else if(strncmp(line, "Umask", 5) == 0)
    {
      char uMaskBuffer[5];
      uint16_t uMask = 0;

      pChar = &line[5];
      pChar = progressPointerToData(pChar);

      
      strncpy(uMaskBuffer, pChar, 4);
      hexToDecimal(uMaskBuffer,&uMask);
      process->uMask = (uint16_t) uMask;

      printf("Process Umask:                           0x%04x\n", process->uMask);
    }

    else if(strncmp(line, "State", 5) == 0)
    {
      pChar = &line[5];
      pChar = progressPointerToData(pChar);
      
      process->state = *pChar;

      printf("State:                               %10c\n", process->state);
    }

    else if(strncmp(line, "Tgid", 4) == 0)
    {
      pChar = &line[4];
      pChar = progressPointerToData(pChar);

      process->tgid = atoi(pChar);

      printf("Tgid:                                %10u\n", process->tgid);
    }

    else if(strncmp(line, "Ngid", 4) == 0)
    {
      pChar = &line[4];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->ngid = atoi(pChar);
      }
      else
      {
        process->ngid = 0;
      }

      printf("Ngid:                                %10u\n", process->ngid);
    }

    else if(strncmp(line, "PPid", 4) == 0)
    {
      pChar = &line[6];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->PPID = atoi(pChar);
      }

      printf("PPid:                                %10u\n", process->PPID);
    }

    else if(strncmp(line, "TracerPid", 9) == 0)
    {
      pChar = &line[9];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->tracerPID = atoi(pChar);
      }

      printf("Tracer PID:                          %10u\n", process->tracerPID);
    }

    else if(strncmp(line, "Uid", 4) == 0)
    {
      pChar = &line[4];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->uid = atoi(pChar);
      }

      printf("Process UID:                         %10u\n", process->uid);
    }

    else if(strncmp(line, "Gid", 4) == 0)
    {
      pChar = &line[4];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->gid = atoi(pChar);
      }

      printf("Process GID:                         %10u\n", process->gid);
    }

    else if(strncmp(line, "FDSize", 6) == 0)
    {
      pChar = &line[6];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->fileDescriptorSize = atoi(pChar);
      }
      else
      {
        process->fileDescriptorSize = 0;
      }

      printf("FD Size:                             %10u\n", process->fileDescriptorSize);
    }

/*
 * TODO: Fix this to read the list of 
 * supplementary groups the process belongs to.
*/
    // else if(strncmp(line, "Groups", 6) == 0)
    // {
    //   pChar = &line[6];
    //   pChar = progressPointerToData(pChar);

    //   if(isdigit(*pChar))
    //   {
    //   {
    //     process->groups[0] = 0;
    //   }

    //   printf("Groups: %u\n", process->groups);
    // }

    else if(strncmp(line, "Kthread", 7) == 0)
    {
      pChar = &line[7];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->kThread = atoi(pChar);
        if(process->kThread == 1)
        {
          printf("Kernel Thread:                              YES\n\n");
        }
        else
        {
          printf("Kernel Thread:                               NO\n\n");
        }
      }
      else
      {
        process->kThread = 0;
        printf("Kernel Thread:                               NO\n\n");
      }

    }

    else if(strncmp(line, "VmPeak", 6) == 0)
    {
      pChar = &line[6];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->vmPeak = atoi(pChar);
      }
      else
      {
        process->vmPeak = 0;
      }

      printf("Virtual Memory Peak:                     %10u kB\n", process->vmPeak);
    }

    else if(strncmp(line, "VmSize", 6) == 0)
    {
      pChar = &line[6];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->vmSize = atoi(pChar);
      }
      else
      {
        process->vmSize = 0;
      }

      printf("Virtual Memory Size:                     %10u kB\n", process->vmSize);
    }

    else if(strncmp(line, "VmLck", 5) == 0)
    {
      pChar = &line[5];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->vmLock = atoi(pChar);
      }
      else
      {
        process->vmLock = 0;
      }

      printf("Virtual Locked Memory Size:              %10u kB\n", process->vmLock);
    }

    else if(strncmp(line, "VmPin", 5) == 0)
    {
      pChar = &line[5];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->vmPin = atoi(pChar);
      }
      else
      {
        process->vmPin = 0;
      }

      printf("Virtual Pinned Memory Size:              %10u kB\n", process->vmPin);
    }

  //peak resident set size ("high water mark").
    else if(strncmp(line, "VmHWM", 5) == 0)
    {
      pChar = &line[5];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->vmHWM = atoi(pChar);
      }
      else
      {
        process->vmHWM = 0;
      }

      printf("Virtual Memory High Water Mark:          %10u kB\n", process->vmHWM);
    }

    else if(strncmp(line, "VmRSS", 5) == 0)
    {
      pChar = &line[5];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->vmRSS = atoi(pChar);
      }
      else
      {
        process->vmRSS = 0;
      }

      printf("Total Size Of Memory Portions:           %10u kB\n", process->vmRSS);
    }

    else if(strncmp(line, "RssAnon", 7) == 0)
    {
      pChar = &line[7];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->rssAnon = atoi(pChar);
      }
      else
      {
        process->rssAnon = 0;
      }

      printf("Size Of Resident Anonymous Memory:       %10u kB\n", process->rssAnon);
    }

    else if(strncmp(line, "RssFile", 7) == 0)
    {
      pChar = &line[7];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->rssFile = atoi(pChar);
      }
      else
      {
        process->rssFile = 0;
      }

      printf("Size Of Resident File Mappings:          %10u kB\n", process->rssFile);
    }

    else if(strncmp(line, "RssShmem", 8) == 0)
    {
      pChar = &line[8];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->rssShmem = atoi(pChar);
      }
      else
      {
        process->rssShmem = 0;
      }

      printf("Size Of Resident Shmem Memory:           %10u kB\n", process->rssShmem);
    }

    else if(strncmp(line, "VmData", 6) == 0)
    {
      pChar = &line[6];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->vmData = atoi(pChar);
      }
      else
      {
        process->vmData = 0;
      }

      printf("Size Of Private Data Segments:           %10u kB\n", process->vmData);
    }

    else if(strncmp(line, "VmStk", 5) == 0)
    {
      pChar = &line[5];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->vmStack = atoi(pChar);
      }
      else
      {
        process->vmStack = 0;
      }

      printf("Size Of Stack Segments:                  %10u kB\n", process->vmStack);
    }

    else if(strncmp(line, "VmExe", 5) == 0)
    {
      pChar = &line[5];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->vmExe = atoi(pChar);
      }
      else
      {
        process->vmExe = 0;
      }

      printf("Size Of Text Segments:                   %10u kB\n", process->vmExe);
    }
    
    else if(strncmp(line, "VmLib", 5) == 0)
    {
      pChar = &line[5];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->vmLib = atoi(pChar);
      }
      else
      {
        process->vmLib = 0;
      }

      printf("Size Of Shared Library Code:             %10u kB\n", process->vmLib);
    }

    else if(strncmp(line, "VmPTE", 5) == 0)
    {
      pChar = &line[5];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->vmPTE = atoi(pChar);
      }
      else
      {
        process->vmPTE = 0;
      }

      printf("Size Of Page Table Entries:              %10u kB\n", process->vmPTE);
    }

    else if(strncmp(line, "VmSwap", 6) == 0)
    {
      pChar = &line[6];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->vmSwap = atoi(pChar);
      }
      else
      {
        process->vmSwap = 0;
      }

      printf("Size Of Swap Memory Used By Anon Private Date:         %10u kB\n\n", process->vmSwap);
    }

    else if(strncmp(line, "CoreDumping", 11) == 0)
    {
      pChar = &line[11];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->coreDumping = atoi(pChar);
      }
      else
      {
        process->coreDumping = 0;
      }

      printf("Core Dumping:                        %10u\n", process->coreDumping);
    }

    else if(strncmp(line, "THP_enabled", 11) == 0)
    {
      pChar = &line[11];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->thpEnabled = atoi(pChar);
      }
      else
      {
        process->thpEnabled = 0;
      }

      printf("THP_enabled:                         %10u\n", process->thpEnabled);
    }

    else if(strncmp(line, "Threads", 7) == 0)
    {
      pChar = &line[7];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->threads = atoi(pChar);
      }
      else
      {
        process->threads = 0;
      }

      printf("Threads:                             %10u\n", process->threads);
    }

    else if(strncmp(line, "SigQ", 4) == 0)
    {
      pChar = &line[4];
      pChar = progressPointerToData(pChar);

      strcpy(process->signalQueue, pChar);

      printf("Signal Queue:                           %s\n", process->signalQueue);
    }

    else if(strncmp(line, "SigPnd", 6) == 0)
    {
      pChar = &line[6];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        hexToDecimal(pChar, &process->threadSignalsPendingMask);
      }
      else
      {
        process->threadSignalsPendingMask = 0;
      }

      printf("Bitmap Of Thread Signals Pending:    0x%08x\n", process->threadSignalsPendingMask);
    }

    else if(strncmp(line, "ShdPnd", 6) == 0)
    {
      pChar = &line[6];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        hexToDecimal(pChar, &process->processSignalsPendingMask);
      }
      else
      {
        process->processSignalsPendingMask = 0;
      }

      printf("Bitmap Of Process Signals Pending:   0x%08x\n", process->processSignalsPendingMask);
    }

    else if(strncmp(line, "SigBlk", 6) == 0)
    {
      pChar = &line[6];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        hexToDecimal(pChar, &process->blockedSignalsMask);
      }
      else
      {
        process->blockedSignalsMask = 0;
      }

      printf("Bitmap Of Blocked Signals:           0x%08x\n", process->blockedSignalsMask);
    }

    else if(strncmp(line, "SigIgn", 6) == 0)
    {
      pChar = &line[6];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        hexToDecimal(pChar, &process->ignoredSignalsMask);
      }
      else
      {
        process->ignoredSignalsMask = 0;
      }

      printf("Bitmap Of Ignored Signals:           0x%08x\n", process->ignoredSignalsMask);
    }

    else if(strncmp(line, "SigCgt", 6) == 0)
    {
      pChar = &line[6];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        hexToDecimal(pChar, &process->caughtSignalsMask);
      }
      else
      {
        process->caughtSignalsMask = 0;
      }

      printf("Bitmap Of Caught Signals:            0x%08x\n", process->caughtSignalsMask);
    }

    else if(strncmp(line, "CapInh", 6) == 0)
    {
      pChar = &line[6];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        hexToDecimal(pChar, &process->InheritablecapabilitiesMask);
      }
      else
      {
        process->InheritablecapabilitiesMask = 0;
      }

      printf("Bitmap Inheritable Capabilities:     0x%08x\n", process->InheritablecapabilitiesMask);
    }

    else if(strncmp(line, "CapPrm", 6) == 0)
    {
      pChar = &line[6];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        hexToDecimal(pChar, &process->permittedCapabilitiesMask);
      }
      else
      {
        process->permittedCapabilitiesMask = 0;
      }

      printf("Bitmap Permitted:                    0x%08x\n", process->permittedCapabilitiesMask);
    }

    else if(strncmp(line, "CapEff", 6) == 0)
    {
      pChar = &line[6];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        hexToDecimal(pChar, &process->processSignalsPendingMask);
      }
      else
      {
        process->permittedCapabilitiesMask = 0;
      }

      printf("Bitmap Effective Capabilities:       0x%08x\n", process->permittedCapabilitiesMask);
    }

    else if(strncmp(line, "CapBnd", 6) == 0)
    {
      pChar = &line[6];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        hexToDecimal(pChar, &process->boundingCapabilitiesMask);
      }
      else
      {
        process->boundingCapabilitiesMask = 0;
      }

      printf("Bitmap Of Bounding Capabilities:     0x%08x\n", process->boundingCapabilitiesMask);
    }

    else if(strncmp(line, "CapAmb", 6) == 0)
    {
      pChar = &line[6];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        hexToDecimal(pChar, &process->permittedCapabilitiesMask);
      }
      else
      {
        process->permittedCapabilitiesMask = 0;
      }

      printf("Bitmap Effective Capabilities:       0x%08x\n\n", process->permittedCapabilitiesMask);
    }

    else if(strncmp(line, "NoNewPrivs", 10) == 0)
    {
      pChar = &line[10];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->noNewPrivs = atoi(pChar);
      }
      else
      {
        process->noNewPrivs = 0;
      }

      printf("No New Priviledges:                   %10u\n", process->noNewPrivs);
    }

    else if(strncmp(line, "Seccomp", 7) == 0)
    {
      pChar = &line[7];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->secComp = atoi(pChar);
      }
      else
      {
        process->secComp = 0;
      }

      printf("Seccomp Mode:                         %10u\n", process->secComp);
    }

    else if(strncmp(line, "Speculation_Store_Bypass", 24) == 0)
    {
      pChar = &line[24];
      pChar = progressPointerToData(pChar);

      strcpy(process->speculationStoreBypass, pChar);

      printf("Speculation Store Bypass:                         %s\n", process->speculationStoreBypass);
    }

    else if(strncmp(line, "SpeculationIndirectBranch", 25) == 0)
    {
      pChar = &line[25];
      pChar = progressPointerToData(pChar);

      strcpy(process->speculationIndirectBranch, pChar);

      printf("Speculation Indirect Branch:                         %s\n", process->speculationIndirectBranch);
    }














    memset(line, 0, sizeof(line));
    // printf("\n");
  }

  printf("\n\n\n");

  fclose(fileHandle);
  return ERR_NONE;
}

int16_t retrieveRunningProcessesData(TVector * vec)
{
  DIR * procDir = opendir("/proc");
  TRunningProcess process = {0};
  struct dirent * ent;
  uint16_t numProcesses = 0;
  long pid;
  uint8_t err = ERR_NONE;

  if(procDir == NULL)
  {
      perror("Failed To Open /proc Directory");
      return ERR_DIRECTORY_OPERATION_FAILED;
  }

  while(ent = readdir(procDir))
  {
      if(isdigit(*ent->d_name))
      {
        pid = strtol(ent->d_name, NULL, 10);
        process.PID = pid;
        if(pid != 1)
        {
          err = retrieveRunningProcessData(&process);
        }
        
        // printf("PID = %lu\n", pid);
        
        numProcesses += 1;
        memset(&process, 0, sizeof(TRunningProcess));
      }

  }
  printf("\nNumber Of Processes: %lu", numProcesses);

  closedir(procDir);
  return ERR_NONE;
}