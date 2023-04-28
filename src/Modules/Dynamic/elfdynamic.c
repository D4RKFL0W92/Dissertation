#include <signal.h>
#include "elfdynamic.h"

static int8_t attachToProcess(pid_t pid)
{


  if(ptrace(PTRACE_ATTACH, pid, 0, 0) == -1)
  {
    #ifdef DEBUG
    perror("ERROR CALLING: ptrace(PTRACE_ATTACH, pid, 0, 0)");
    #endif
    return FAILED;
  }
  return SUCCESS;
}

static int8_t detachFromProcess(pid_t pid)
{


  if(ptrace(PTRACE_DETACH, pid, 0, 0) == -1)
  {
    #ifdef DEBUG
    perror("ERROR CALLING: ptrace(PTRACE_DETACH, pid, 0, 0)");
    #endif
    return FAILED;
  }
  return SUCCESS;
}

static int8_t getRegisterValues(int pid, struct user_regs_struct* regs)
{

  const char *func_name = "getRegisterValues()";
 
  struct user_regs_struct* registers; 
  
  if(ptrace(PTRACE_GETREGS, pid, NULL, regs) == -1)
  {
    #ifdef DEBUG
    perror("ERROR CALLING: ptrace(PTRACE_GETREGS, pid, NULL, registers)");
    #endif

    return FALSE;
  }

  return TRUE;
}

uint64_t getSymbolAddr(char* p_Mem, char* symbolName)
{
  char* strtab;
  uint16_t entries;
  /* If not an ELF the next check makes no sense. */
  if(p_Mem[0] != 0x7f || p_Mem[1] != 'E' || p_Mem[2] != 'L' || p_Mem[3] != 'F')
  {
    return 0;
  }

  if(p_Mem[4] == ELFCLASS32)
  {
    Elf32_Ehdr* ehdr;
    Elf32_Shdr* shdr;
    Elf32_Sym*  sym;

    ehdr = (Elf32_Ehdr *) p_Mem;
    
    if(!ehdr->e_shoff || !ehdr->e_shnum || !ehdr->e_shentsize)
    {
      /* No section header information found. */
      return 0;
    }

    shdr = (Elf32_Shdr*) ((char*)ehdr + ehdr->e_shoff);
    printf("%d Sections.\n Startin from offset: 0x%08x\n %d bytes apart.\n", ehdr->e_shnum, ehdr->e_shoff, ehdr->e_shentsize);

    /* Loop through the section headers until we find the symtab. */
    for(uint16_t i = 0; i < ehdr->e_shnum; i++)
    {
      if(shdr[i].sh_type == SHT_SYMTAB)
      {
        sym = (Elf32_Sym *) shdr[i].sh_offset;
        printf("Symtab address: 0x%08x\n", shdr[i].sh_offset);
      }
    }

    return 0;
  }
  else if(p_Mem[4] == ELFCLASS64)
  {
    Elf64_Ehdr* ehdr;
    Elf64_Shdr* shdr;
    Elf64_Sym*  sym;

    ehdr = (Elf64_Ehdr *) p_Mem;

    if(!ehdr->e_shoff || !ehdr->e_shnum || !ehdr->e_shentsize)
    {
      /* No section header information found. */
      return 0;
    }

    shdr = (Elf64_Shdr*) ((char*)ehdr + ehdr->e_shoff);
    printf("%d Sections.\nHeaders startin from offset: 0x%08x\n%d bytes apart.\n", ehdr->e_shnum, ehdr->e_shoff, ehdr->e_shentsize);

    /* Loop through the section headers until we find the addresses
     * of the symtab and strtab.
     */
    for(uint16_t i = 0; i < ehdr->e_shnum; i++)
    {
      if(shdr[i].sh_type == SHT_SYMTAB)
      {
        sym = (Elf64_Sym *) shdr[i].sh_offset;
        /* Number of entries can vary per section. */
        entries = shdr[i].sh_size / sizeof(Elf64_Sym);
        printf("Symtab address: 0x%08x\nNumber of entries per section: %d\n", shdr[i].sh_offset, entries);
      }
      else if(shdr[i].sh_type == SHT_STRTAB)
      {
        /* .shstrtab should be the last strtab of the file
         * (there are multiple shdrs marked as SHT_STRTAB).
         */
        strtab = ((char *) shdr[i].sh_offset);
        printf("Strtab address: 0x%08x\n", shdr[i].sh_offset);
      }

      if(entries && sym && strtab)
      {
        for(uint16_t i = 0; i < entries; i++)
        {
          char *tmpStr = &strtab[sym->st_name];
          if(!strncmp(tmpStr, symbolName, strlen(symbolName)))
          {
            /* A match has been found, return the address related to symbol. */
            return (uint64_t) sym->st_value;
          }  
        }
      }
    }
    
    return 0;
  }
  else
  {
    return 0;
  }

}

int16_t beginProcessTrace(const char* p_procName, int argc, char** argv, char** envp)
{
  struct user_regs_struct registers;
  pid_t pid;
  enum BITS arch;
  uint64_t exec_sz;
  uint8_t* p_mem;
  int child_state;
  
  if( (p_mem = mapELFToMemory(p_procName, &arch, &exec_sz)) == NULL)
  {
    #ifdef DEGUG
    perror("ERROR: Cannot map executable to memory.")
    #endif
    return FAILED;
  }
    

  if((pid = fork()) < 0)
  {
    #ifdef DEBUG
    perror("ERROR forking process.");
    #endif
    return FAILED;
  }

  if(pid == 0) /* Child process */
  {
    if(ptrace(PTRACE_TRACEME, pid, NULL, NULL) < 0)
    {
      #ifdef DEBUG
      perror("ERROR calling PTRACE_TRACEME");
      #endif
      return FAILED;
    }
    // execve the process we intend to trace.
    execve(p_procName, argv, envp);
  }

  
  else
  {
    if(wait(&child_state) == FAILED) /* Wait for state change of child process. */
    {
      perror("ERROR calling wait from parent.");
      exit(FAILED);
    }

    do
    {
      if(ptrace(PTRACE_GETREGS, pid, 0, &registers) != 0)
      {
        perror("ERROR getting register values.");
        exit(-1);
      }

      printf("RIP:\t0x%016x\n", registers.rip);
      
      if(ptrace(PTRACE_SINGLESTEP, pid, 0, 0) != 0)
      {
        perror("ERROR calling PTRACE_SINGLESTEP on child process.");
        exit(-1);
      }

      wait(&child_state);

    } while (child_state != SIGCHLD || child_state != SIGTRAP);
    
  }

  return TRUE;
}

int8_t dump_memory(pid_t pid, uint64_t startAddr, uint64_t uCount)
{
  char* pMem;
  uint64_t tmp;
  uint64_t iterations;

  if(uCount == 0) { return FAILED; }

  tmp = uCount / 8; /* Divide by intel word size rounding down */
  iterations = \
    ((float)(tmp * 8) == uCount) ? tmp : (uint64_t)(tmp) + 1; /* Check tmp is integer value. */
  

  if( (pMem = malloc(uCount)) == NULL)
  {
    perror("ERROR allocating memory for read.");
    return FAILED;
  }

  /* Print top of grid. */
  PRINT_GRID_TOP;

  for(uint64_t i = 0; i < iterations; ++i)
  {
    if(ptrace(PTRACE_PEEKDATA, pid, startAddr + (i*8), pMem + (i*8)) == FAILED)
    {
      perror("ERROR calling PTRACE_PEEKDATA");
      return FAILED;
    }
    printf("0x%016x %02x %02x %02x %02x, %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", startAddr + (i*8), \
      *(pMem + (i*8)), *(pMem + (i*8) + 1), *(pMem + (i*8) + 2), *(pMem + (i*8) + 3), *(pMem + (i*8) + 4), \
      *(pMem + (i*8) + 5), *(pMem + (i*8) + 6), *(pMem + (i*8) + 7), *(pMem + (i*8) + 8), *(pMem + (i*8) + 9), \
      *(pMem + (i*8) + 10), *(pMem + (i*8) + 11), *(pMem + (i*8) + 12), *(pMem + (i*8) +13), *(pMem + (i*8) + 14), \
      *(pMem + (i*8) + 15));
  }

  free(pMem); /* Deallocate memory. */
  return SUCCESS;
}