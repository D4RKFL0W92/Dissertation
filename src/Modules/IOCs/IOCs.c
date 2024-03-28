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
    char * pChar = NULL;

    
    if(strncmp(line, "Name", 4) == 0)
    {
      pChar = &line[4];
      pChar = progressPointerToData(pChar);

      strcpy(process->name, pChar);
      printf("Process Name: %s\n", process->name);
      printf("Process PID: %u\n", process->PID);
    }

    else if(strncmp(line, "Umask", 5) == 0)
    {
      char uMaskBuffer[5];
      uint16_t uMask = 0;

      pChar = &line[6];
      pChar = progressPointerToData(pChar);

      
      strncpy(uMaskBuffer, pChar, 4);
      hexToDecimal(uMaskBuffer,&uMask);
      process->uMask = (uint16_t) uMask;

      printf("Process Umask: 0x%04x\n", process->uMask);
    }

    else if(strncmp(line, "State", 5) == 0)
    {
      char state = '\0';

      pChar = &line[5];
      pChar = progressPointerToData(pChar);
      
      process->state = *pChar;

      printf("State: %c\n", process->state);
    }

    else if(strncmp(line, "Tgid", 4) == 0)
    {
      pChar = &line[6];

      strcpy(tmpBuff, pChar);

      tgid = atoi(pChar);
      process->tgid = tgid;

      printf("Tgid: %u\n", tgid);
    }

    else if(strncmp(line, "Ngid", 4) == 0)
    {
      pChar = &line[6];

      if(isdigit(*pChar))
      {
        process->ngid = atoi(pChar);
      }
      else
      {
        process->ngid = 0;
      }

      printf("Ngid: %u\n", process->ngid);
    }

    else if(strncmp(line, "PPid", 4) == 0)
    {
      pChar = &line[6];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->PPID = atoi(pChar);
      }

      printf("PPid: %u\n", process->PPID);
    }

    else if(strncmp(line, "TracerPid", 9) == 0)
    {
      pChar = &line[9];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->tracerPID = atoi(pChar);
      }

      printf("Tracer PID: %u\n", process->tracerPID);
    }

    else if(strncmp(line, "Uid", 4) == 0)
    {
      pChar = &line[4];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->uid = atoi(pChar);
      }

      printf("Process UID: %u\n", process->uid);
    }

    else if(strncmp(line, "Gid", 4) == 0)
    {
      pChar = &line[4];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->gid = atoi(pChar);
      }

      printf("Process GID: %u\n", process->gid);
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

      printf("FD Size: %u\n", process->fileDescriptorSize);
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
    //     process->groups[0] = atoi(pChar);
    //   }
    //   else
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
          printf("Kernel Thread: YES\n");
        }
        else
        {
          printf("Kernel Thread: NO\n");
        }
      }
      else
      {
        process->kThread = 0;
        printf("Kernel Thread: NO\n");
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

      printf("Virtual Memory Peak: %u kB\n", process->vmPeak);
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

      printf("Virtual Memory Size: %u kB\n", process->vmSize);
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

      printf("Virtual Locked Memory Size: %u kB\n", process->vmLock);
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

      printf("Virtual Pinned Memory Size: %u kB\n", process->vmPin);
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

      printf("Virtual Memory High Water Mark: %u kB\n", process->vmHWM);
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

      printf("Total Size Of Memory Portions: %u kB\n", process->vmRSS);
    }

    else if(strncmp(line, "RssAnon", 5) == 0)
    {
      pChar = &line[5];
      pChar = progressPointerToData(pChar);

      if(isdigit(*pChar))
      {
        process->rssAnon = atoi(pChar);
      }
      else
      {
        process->rssAnon = 0;
      }

      printf("Size Of Resident Anonymous Memory: %u kB\n", process->rssAnon);
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