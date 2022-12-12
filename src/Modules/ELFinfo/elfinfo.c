#include "elfinfo.h"

static enum BITS isELF(char* arch)
{
    if(arch == NULL || strlen(arch) < 6)
        return T_NO_ELF;

    if(arch[0] != 0x7f || arch[1] != (uint8_t)'E' ||
        arch[2] != (uint8_t)'L' || arch[3] != (uint8_t)'F')
        return T_NO_ELF;

    unsigned char endianness = arch[5];
    if(endianness != ELFDATANONE && endianness != ELFDATA2LSB && endianness != ELFDATA2MSB)
        return T_NO_ELF; // // Likely not an ELF executable

    // Check and return intended architecture for the binary.
    unsigned char arch_bit = arch[4];
    if(ELFCLASS32 == arch_bit)
    {
        return T_32;
    }
    else if(ELFCLASS64 == arch_bit)
    {
        return T_64;
    }
}

char* mapELFToMemory(const char* filepath, enum BITS* arch, uint64_t* map_sz)
{
    #ifdef DEBUG
    char* func_name = "mapELFToMemory()";
    #endif
    ssize_t bytes_read;
    char MAGIC[6];
    char* file_mem;
    int fd, ret;
    struct stat st;

    if( (fd = open(filepath, O_RDONLY)) < 0)
    {
        // Should really log errors/failures.
        #ifdef DEBUG
        logEvent(LOG_FILE, func_name, "open()");
        perror("Unable to open() file inside mapELFToMemory().");
        #endif
        return NULL;
    }

    if(fstat(fd, &st) < 0)
    {
        #ifdef DEBUG
        logEvent(LOG_FILE, func_name, "fstat()");
        perror("Unable to fstat() file inside mapELFToMemory().");
        #endif
        return NULL;
    }

    // Check is an ELF file before mapping into memory.
    if( (bytes_read = read(fd, MAGIC, 6)) < 6)
    {
        #ifdef DEBUG
        logEvent(LOG_FILE, func_name, "read()");
        perror("Unable to read() file inside mapELFToMemory().");
        #endif
      
        return NULL;
    }
    
    // if( (*arch = isELF(MAGIC)) == T_NO_ELF) // Store the architecture of the binary for use later.
    // {
    //     #ifdef DEBUG
    //     logEvent(LOG_FILE, func_name, "isELF()");
    //     perror("File being read is not an ELF file.");
    //     #endif
        
    //     return NULL;
    // }

    *map_sz = st.st_size; // Store size of ELF file for later use.

    if( (file_mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    {
        #ifdef DEBUG
        logEvent(LOG_FILE, func_name, "mmap()");
        perror("Unable to mmap() in mapELFToMemory().");
        #endif
        return NULL;
    }

    close(fd);
    return file_mem;
}

int8_t mapELF64ToHandleFromFileHandle(FILE_HANDLE_T* fileHandle, ELF64_EXECUTABLE_HANDLE_T* elfHandle)
{
    if(fileHandle == NULL)
    {
        return FAILED;
    }

    /* TODO: Check it is definitely Elf64_Phdr before proceeding. */

    elfHandle->fileHandle = *fileHandle;
    elfHandle->ehdr       = (Elf64_Ehdr *) &fileHandle->p_data[0];
    elfHandle->phdr       = (Elf64_Phdr *) &fileHandle->p_data[ elfHandle->ehdr->e_phoff ];
    elfHandle->shdr       = (Elf64_Shdr *) &fileHandle->p_data[ elfHandle->ehdr->e_shoff ];

    return SUCCESS;
}

uint64_t getELFEntry(char* filepath)
{
    uint8_t* p_mem;
    enum BITS arch;
    uint64_t file_sz;

    p_mem = mapELFToMemory(filepath, &arch, &file_sz);

    if(arch == T_64)
    {
        return getELF64Entry(p_mem);
    }
    else if(arch == T_32)
    {
        return getELF32Entry(p_mem);
    }
}

static Elf32_Addr getELF32Entry(uint8_t* p_mem)
{
    Elf32_Ehdr* ehdr = (Elf32_Ehdr *) p_mem;
    return ehdr->e_entry;
}

static Elf64_Addr getELF64Entry(uint8_t* p_mem)
{
    Elf64_Ehdr* ehdr = (Elf64_Ehdr *) p_mem;
    return ehdr->e_entry;
}


uint8_t printELFInfo(const char* elf_filepath, const char* output_filepath)
{
    #ifdef DEBUG
    const char *func_name = "printELFInfo()";
    #endif

    char ehdr_buf[ sizeof(Elf64_Ehdr) ];
    char MAGIC[6];

    char class[4];
    char endian[8];
    char elf_type[16];
    char arch[16];
    char stripped[8];

    struct stat st;
    
    uint32_t e32_entry = 0;
    uint64_t e64_entry = 0;

    enum BITS bits;
    int fd;
    ssize_t read_ret;

    if(elf_filepath == NULL) return FALSE;

    if( (fd = open(elf_filepath, O_RDONLY)) < 0)
    {
        #ifdef DEBUG
        perror("Unable to open() file in printELFInfo().");
        #endif

        logEvent(LOG_FILE, func_name, "open()");
        close(fd);
        return FALSE;
    }

    if(fstat(fd, &st) == -1)
    {
        #ifdef DEBUG
        perror("Unable to stat() ELF file in printELFInfo().");
        logEvent(LOG_FILE, func_name, "fstat()");
        #endif

        close(fd);
        return FALSE;
    }

    if(read(fd, MAGIC, sizeof(MAGIC)) == -1)
    {
        #ifdef DEBUG
        perror("Unable to read() magic bytes of file in printELFInfo().");
        logEvent(LOG_FILE, func_name, "read()");
        #endif

        
        close(fd);
        return FALSE;
    }

    /*
        Reset the file cursor to read in the ELF header.
    */
    if(lseek(fd, 0, SEEK_SET) < 0) // Return to start of the file
    {
        #ifdef DEBUG
        perror("Unable to lseek() to start of file in printELFInfo().");
        #endif

        logEvent(LOG_FILE, func_name, "lseek()");
        close(fd);
        return FALSE;
    }

    /* Only read sizeof elf MAGIC number until we are sure it's an ELF */
    bits = isELF(MAGIC);

    /*
        Get endianess of the ELF file. This is alwas stored in the sixth byte of the file.
    */
    switch(MAGIC[5])
    {
        case ELFDATA2LSB:
            strcpy(endian, ENDIAN_LITTLE);
            break;

        case ELFDATA2MSB:
            strcpy(endian, ENDIAN_BIG);
            break;

        case ELFDATANONE:
            close(fd); 
            return FALSE;
    }

    /*
        We can extract the ELF header now (32/64-bit) dependent on the return of isELF().
    */
    if(bits == T_32)
    {
        strcpy(class, CLASS32); // Assign bit size to a string for printing.

        Elf32_Ehdr* ehdr;
        read_ret = read(fd, ehdr_buf, sizeof(Elf32_Ehdr));

        if(read_ret == -1 || read_ret < sizeof(Elf32_Ehdr))
        {
            #ifdef DEBUG
            perror("Error reading Elf32_Ehdr in printELFInfo()");
            #endif
            logEvent(LOG_FILE, func_name, "reading Elf32_Ehdr");
            close(fd);
            return FALSE;
        }
        ehdr = (Elf32_Ehdr *)ehdr_buf;
        switch(ehdr->e_type)
        {
            case ET_REL:
                strcpy(elf_type, ELF_REL_T);
                break;

            case ET_EXEC:
                strcpy(elf_type, ELF_EXEC_T);
                break;

            case ET_DYN:
                strcpy(elf_type, ELF_DYN_T);
                break;

            case ET_CORE:
                strcpy(elf_type, ELF_CORE_T);
                break;

            case ET_NONE:
                strcpy(elf_type, ELF_UNKNOWN_T);
                break;
        }
        /* Check if the binary is stripped by checking for a section header */
        if(ehdr->e_shoff == 0)
            strcpy(stripped, TRUE_STR);
        else
            strcpy(stripped, FALSE_STR);

        e32_entry = ehdr->e_entry;
        
    }
    else if(bits == T_64)
    {
        strcpy(class, CLASS64); // Assign bit size to a string for printing.
        Elf64_Ehdr* ehdr;
        read_ret = read(fd, ehdr_buf, sizeof(Elf64_Ehdr));

        if(read_ret == -1 || read_ret < sizeof(Elf64_Ehdr))
        {
            #ifdef DEBUG
            perror("Error reading Elf64_Ehdr in printELFInfo()");
            #endif
            logEvent(LOG_FILE, func_name, "reading Elf64_Ehdr");
            close(fd);
            return FALSE;
        }
        ehdr = (Elf64_Ehdr *)ehdr_buf;
        switch(ehdr->e_type)
        {
            case ET_REL:
                strcpy(elf_type, ELF_REL_T);
                break;

            case ET_EXEC:
                strcpy(elf_type, ELF_EXEC_T);
                break;

            case ET_DYN:
                strcpy(elf_type, ELF_DYN_T);
                break;

            case ET_CORE:
                strcpy(elf_type, ELF_CORE_T);
                break;

            case ET_NONE:
                strcpy(elf_type, ELF_UNKNOWN_T);
                break;
        }
        /* Check if the binary is stripped by checking for a section header */
        if(ehdr->e_shoff == 0)
            strcpy(stripped, TRUE_STR);
        else
            strcpy(stripped, FALSE_STR);

        e64_entry = ehdr->e_entry;
    }
    else
    {
        close(fd);
        return FALSE;
    }
    /* Print tablized ELF binary iinformation */
    

    if(output_filepath != NULL)
    {
        FILE* out = fopen(output_filepath, "a+");
        if(fopen == NULL)
        {
            #ifdef DEBUG
            logEvent(LOG_FILE, "printELFInfo()", "fopen()");
            #endif
            goto failed_file_open; // Resonable use of goto to reduce code duplication (A break could probably be used but this is explicit)
        }
        fprintf(out, "------------------------------- ELF Binary Information -------------------------------\n\n");
        if(e32_entry == 0) // Must be 64-bit
            fprintf(out, "\nELF Class:\t%s-BIT\nEndianess:\t%s\nELF Type:\t%s\nStripped:\t%s\nEntry:\t\t0x%08x\nFile Size:\t0x%08x\n",
                class, endian, elf_type, stripped, e64_entry, st.st_size);
        else
            fprintf(out, "\nELF Class:\t%s-BIT\nEndianess:\t%s\nELF Type:\t%s\nStripped:\t%s\nEntry:\t\t0x%08x\nFile Size:\t0x%08x\n",
                class, endian, elf_type, stripped, e32_entry, st.st_size);
        fclose(out);
        close(fd);
        return TRUE;
    }
    else
    {
        failed_file_open:
        puts("------------------------------- ELF Binary Information -------------------------------\n\n");
        if(e32_entry == 0) // Must be 64-bit
            printf("\nELF Class:\t%s-BIT\nEndianess:\t%s\nELF Type:\t%s\nStripped:\t%s\nEntry:\t\t0x%08x\nFile Size:\t0x%08x\n",
                class, endian, elf_type, stripped, e64_entry, st.st_size);
        else
            printf("\nELF Class:\t%s-BIT\nEndianess:\t%s\nELF Type:\t%s\nStripped:\t%s\nEntry:\t\t0x%08x\nFile Size:\t0x%08x\n",
                class, endian, elf_type, stripped, e32_entry, st.st_size);
        
        close(fd);
        return TRUE;
    }
}

int8_t printElfInfoVerbose(FILE_HANDLE_T* fileHandle)
{
    enum BITS arch;
    char MAGIC[6];

    if(fileHandle->p_data == NULL)
    {
        return FAILED;
    }

    strncpy(MAGIC, fileHandle->p_data, 6);
    arch = isELF(MAGIC);

    switch(arch)
    {
        /* Find out what size Elf header the binary is. */
        case T_32:
            

            break;

        case T_64:
            ELF64_EXECUTABLE_HANDLE_T elfHandle = {0};

            elfHandle.ehdr = (Elf64_Ehdr *) fileHandle->p_data;
            
            puts("Elf Header:\n");
            dumpHexBytesFromFileHandle(fileHandle, 0, elfHandle.ehdr->e_ehsize);

            puts("Class:\t64 BIT\n");
            printElf64ElfHeader(elfHandle.ehdr);
            printf("\n\n");
            /* TODO: Print Program/Section Headers. */
            mapELF64ToHandleFromFileHandle(fileHandle, &elfHandle);
            puts("Program Headers:\n");
            printELF64ProgramHeaders(&elfHandle);

            puts("Section Headers:\n");
            printELF64SectionHeaders(&elfHandle);

            break;

        case T_NO_ELF:
        default:
            break;

    }
    
}
int8_t printElf64ElfHeader(Elf64_Ehdr* ehdr)
{
    if(ehdr== NULL)
    {
        #ifdef DEBUG
        perror("ERROR, NULL pointer in printElf32ElfHeader()");
        #endif
        return FAILED;
    }
    printf("Elf 64 Header Size:\t0x%08x\n", ehdr->e_ehsize);
    /* Print endianess of binary. */
    printf("Endianess:");
    switch(ehdr->e_ident[EI_DATA])
    {
        case ELFDATA2LSB:
            printf("            LITTLE\n");
            break;
        
        case ELFDATA2MSB:
            printf("               BIG\n");
            break;

        case ELFDATANONE:
        default:
            printf("           UNKNOWN\n");
            break;
    }
    /* Print version. None could indicate tampering. */
    printf("Version:\t");
    switch(ehdr->e_ident[EI_VERSION])
    {
        case EV_CURRENT:
            printf("           CURRENT\n");
            break;

        case EV_NONE:
        default:
            printf("           UNKNOWN\n");
            break;
    }

    printf("ABI:\t");
    switch(ehdr->e_ident[EI_OSABI])
    {
        case ELFOSABI_SYSV:
            printf("              UNIX\n");
            break;

        case ELFOSABI_HPUX:
            printf("             HP-UX\n");
            break;

        case ELFOSABI_NETBSD:
            printf("            NETBSD\n");
            break;

        case ELFOSABI_LINUX:
            printf("             Linux\n");
            break;

        case ELFOSABI_SOLARIS:
            printf("           Solaris\n");
            break;

        case ELFOSABI_IRIX:
            printf("              IRIX\n");
            break;

        case ELFOSABI_FREEBSD:
            printf("           FREEBSD\n");
            break;

        case ELFOSABI_TRU64:
            printf("             TRU64\n");
            break;

        case ELFOSABI_ARM:
            printf("               ARM\n");
            break;

        case ELFOSABI_STANDALONE:
            printf("        STANDALONE\n");
            break;

        default:
            printf("           UNKNOWN\n");
            break;
    }

    printf("Type:\t");
    switch(ehdr->e_type)
    {
        case ET_REL:
            printf("       RELOCATABLE\n");
            break;

        case ET_EXEC:
            printf("        EXECUTABLE\n");
            break;

        case ET_DYN:
            printf("           DYNAMIC\n");
            break;

        case ET_CORE:
            printf("              CORE\n");
            break;

        case ET_NONE:
        default:
            printf("           UNKNOWN\n");
            break;
    }

    printf("Architecture:\t");
    switch(ehdr->e_machine)
    {
        case EM_M32:
            printf("              AT&T\n");
            break;

        case EM_SPARC:
            printf("             SPARC\n");
            break;

        case EM_386:
            printf("       INTEL 80386\n");
            break;

        case EM_68K:
            printf("    MOTOROLA 68000\n");
            break;

        case EM_88K:
            printf("    MOTOROLA 88000\n");
            break;

        case EM_860:
            printf("       INTEL 80860\n");
            break;

        case EM_MIPS:
            printf("              MIPS\n");
            break;

        case EM_PARISC:
            printf("             HP/PA\n");
            break;

        case EM_SPARC32PLUS: /* Could have been tampered with, so we'll keep this here. */
            printf("       SPARC32PLUS\n");
            break;

        case EM_PPC:
            printf("           POWERPC\n");
            break;

        case EM_PPC64:
            printf("         POWERPC64\n");
            break;

        case EM_S390:
            printf("               IBM\n");
            break;

        case EM_ARM:
            printf("               ARM\n");
            break;

        case EM_SH:
            printf("            SUPERH\n");
            break;

        case EM_SPARCV9:
            printf("           SPARC64\n");
            break;

        case EM_IA_64:
            printf("     INTEL ITANIUM\n");
            break;

        case EM_X86_64:
            printf("        AMD x86-64\n");
            break;

        case EM_VAX:
            printf("               VAX\n");
            break;

        case EM_NONE:
        default:
            printf("           UNKNOWN\n");
    }

    printf("File Version\t");
    switch(ehdr->e_version)
    {
        case EV_CURRENT:
            printf("           CURRENT\n");
            break;

        case EV_NONE:
        default:
            printf("           UNKNOWN\n");
            break;
    }
    /* TODO: Add checks. */
    printf("Program Entry:\t0x%08x\n", ehdr->e_entry);
    printf("Program Header Offset:\t0x%08x\n", ehdr->e_phoff);
    printf("Number Of Program Headers:\t0x%08x\n", ehdr->e_phnum);
    printf("Program Header Entry Size:\t0x%08x\n", ehdr->e_phentsize);
    printf("Number Of Section Headers:\t0x%08x\n", ehdr->e_shnum);
    printf("Section Header Entry Size:\t0x%08x\n", ehdr->e_shentsize);
    printf("Section Header STRNDX:\t0x%08x\n", ehdr->e_shstrndx);
    return SUCCESS;
}

int8_t printElf32ElfHeader(Elf32_Ehdr* ehdr)
{

    if(ehdr== NULL)
    {
        #ifdef DEBUG
        perror("ERROR, NULL pointer in printElf32ElfHeader()");
        #endif
        return FAILED;
    }
    printf("Elf 32 Header Size:\t0x%08x\n", ehdr->e_ehsize);
    /* Print endianess of binary. */
    printf("Endianess:\t");
    switch(ehdr->e_ident[EI_DATA])
    {
        case ELFDATA2LSB:
            printf("        LITTLE\n");
            break;
        
        case ELFDATA2MSB:
            printf("           BIG\n");
            break;

        case ELFDATANONE:
        default:
            printf("       UNKNOWN");
            break;
    }
    /* Print version. None could indicate tampering. */
    printf("Version:\t");
    switch(ehdr->e_ident[EI_VERSION])
    {
        case EV_CURRENT:
            printf("       CURRENT\n");
            break;

        case EV_NONE:
        default:
            printf("       UNKNOWN");
            break;
    }

    printf("ABI:\t");
    switch(ehdr->e_ident[EI_OSABI])
    {
        case ELFOSABI_SYSV:
            printf("          UNIX\n");
            break;

        case ELFOSABI_HPUX:
            printf("         HP-UX\n");
            break;

        case ELFOSABI_NETBSD:
            printf("        NETBSD\n");
            break;

        case ELFOSABI_LINUX:
            printf("         Linux\n");
            break;

        case ELFOSABI_SOLARIS:
            printf("       Solaris\n");
            break;

        case ELFOSABI_IRIX:
            printf("          IRIX\n");
            break;

        case ELFOSABI_FREEBSD:
            printf("       FREEBSD\n");
            break;

        case ELFOSABI_TRU64:
            printf("         TRU64\n");
            break;

        case ELFOSABI_ARM:
            printf("           ARM\n");
            break;

        case ELFOSABI_STANDALONE:
            printf("    STANDALONE\n");
            break;

        default:
            printf("       UNKNOWN");
            break;
    }

    printf("Type:\t");
    switch(ehdr->e_type)
    {
        case ET_REL:
            printf("   RELOCATABLE\n");
            break;

        case ET_EXEC:
            printf("    EXECUTABLE\n");
            break;

        case ET_DYN:
            printf("       DYNAMIC\n");
            break;

        case ET_CORE:
            printf("          CORE\n");
            break;

        case ET_NONE:
        default:
            printf("       UNKNOWN");
            break;
    }

    printf("Architecture:\t");
    switch(ehdr->e_machine)
    {
        case EM_M32:
            printf("          AT&T\n");
            break;

        case EM_SPARC:
            printf("         SPARC\n");
            break;

        case EM_386:
            printf("   INTEL 80386\n");
            break;

        case EM_68K:
            printf("MOTOROLA 68000\n");
            break;

        case EM_88K:
            printf("MOTOROLA 88000\n");
            break;

        case EM_860:
            printf("   INTEL 80860\n");
            break;

        case EM_MIPS:
            printf("          MIPS\n");
            break;

        case EM_PARISC:
            printf("         HP/PA\n");
            break;

        case EM_SPARC32PLUS:
            printf("   SPARC32PLUS\n");
            break;

        case EM_PPC:
            printf("       POWERPC\n");
            break;

        case EM_PPC64:
            printf("     POWERPC64\n");
            break;

        case EM_S390:
            printf("           IBM\n");
            break;

        case EM_ARM:
            printf("           ARM\n");
            break;

        case EM_SH:
            printf("        SUPERH\n");
            break;

        case EM_SPARCV9:
            printf("       SPARC64\n");
            break;

        case EM_IA_64:
            printf(" INTEL ITANIUM\n");
            break;

        case EM_X86_64:
            printf("    AMD x86-64\n");
            break;

        case EM_VAX:
            printf("           VAX\n");
            break;

        case EM_NONE:
        default:
            printf("       UNKNOWN");
    }

    printf("File Version\t");
    switch(ehdr->e_version)
    {
        case EV_CURRENT:
            printf("       CURRENT\n");
            break;

        case EV_NONE:
        default:
            printf("       UNKNOWN");
            break;
    }
    /*TODO: Add some checks maybe */
    printf("Program Entry:\t0x%08x\n", ehdr->e_entry);
    printf("Program Header Offset:\t0x%08x\n", ehdr->e_phoff);
    printf("Number Of Program Headers:\t0x%08x\n", ehdr->e_phnum);
    printf("Program Header Entry Size:\t0x%08x\n", ehdr->e_phentsize);
    printf("Number Of Section Headers:\t0x%08x\n", ehdr->e_shnum);
    printf("Section Header Entry Size:\t0x%08x\n", ehdr->e_shentsize);
    printf("Section Header STRNDX:\t0x%08x\n", ehdr->e_shstrndx);

    return SUCCESS;
}


int8_t printELF64ProgramHeaders(ELF64_EXECUTABLE_HANDLE_T* executableHandle)
{
    char flags[PHDR_FLAG_LEN];
    Elf64_Phdr* phdrIter;
    uint32_t phdrSize;

    if(executableHandle->ehdr == NULL || executableHandle->phdr == NULL)
    {
        #ifdef DEBUG
        perror("ERROR NULL pointer in printELF64ProgramHeaders()");
        #endif
        return FAILED;
    }

    if(executableHandle->ehdr->e_phnum == 0 || executableHandle->ehdr->e_phentsize == 0)
    {
        #ifdef DEBUG
        perror("ERROR, NO PHDRS in printELF64ProgramHeaders()");
        #endif
        return FAILED;
    }
    
    phdrSize = (uint32_t)executableHandle->ehdr->e_phentsize;
    phdrIter = (Elf64_Phdr *)&executableHandle->fileHandle.p_data[executableHandle->ehdr->e_phoff];

    for(uint8_t i = 0; i < executableHandle->ehdr->e_phnum; i++)
    {

        printf("Program Header:\t%d\n", i+1);

        dumpHexBytesFromFileHandle(&executableHandle->fileHandle,
            executableHandle->ehdr->e_phoff + (executableHandle->ehdr->e_phentsize * i), sizeof(Elf64_Phdr));
        printf("\n\n");
            
        /* Print the data held in each Phdr in a human readable form. */

        /* First get the program header type. */
        switch(executableHandle->phdr[i].p_type)
        {
            printf("Program Header Type:\t");
            case PT_LOAD:
                printf("PT_LOAD\n");
                break;
            case PT_DYNAMIC:
                printf("PT_DYNAMIC\n");
                break;
            case PT_INTERP: /* This section points to the interpreter. */
                printf("PT_INTERPRETER\n"); /* TODO: Get interpreter. */
                break;
            case PT_NOTE:
                printf("PT_NOTE\n");
                break;
            case PT_PHDR: /* Should only be one of these. */
                printf("PT_LOAD\n"); /* TODO: Confirm there is only one maybe? */
                break;
            case PT_SHLIB:
                printf("PT_SHLIB\n"); /* Not used in standard (could be used for malicious perpuses though. ) */
                break;
            case PT_LOPROC:
                printf("PT_LOPROC\n");
                break; /* LOPROC/HIPROC are processor specific phdrs. */
            case PT_HIPROC:
                printf("PT_HIPROC\n");
                break;
            case PT_GNU_STACK:
                printf("PT_GNU_STACK\n");
                break;
            case PT_NULL:
            default:
                printf("NULL/UNKNOWN\n");
                break;
        }

        switch(executableHandle->phdr[i].p_flags)
        {
            case 1:
                strncpy(flags, "-X-----", PHDR_FLAG_LEN);
                break;
            case 2:
                strncpy(flags, "---W---", PHDR_FLAG_LEN);
                break;
            case 3:
                strncpy(flags, "-X-W---", PHDR_FLAG_LEN);
                break;
            case 4:
                strncpy(flags, "-----R-", PHDR_FLAG_LEN);
                break;
            case 5:
                strncpy(flags, "-X---R-", PHDR_FLAG_LEN);
                break;
            case 6:
                strncpy(flags, "---W-R-", PHDR_FLAG_LEN);
                break;
            case 7:
                strncpy(flags, "-X-W-R-", PHDR_FLAG_LEN);
                break;
        }
        flags[7] = '\0';

        printf("Flags:\t%s\n", flags);
        /* Static offset, seems incorrect. */
        printf("Static Offset:\t0x%08x\n", executableHandle->phdr[i].p_offset);
        printf("Virtual Address:\t0x%08x\n", executableHandle->phdr[i].p_vaddr);
        printf("Physical Address:\t0x%08x\n", executableHandle->phdr[i].p_paddr);

        printf("Header File Image Size:\t0x%08x\n", executableHandle->phdr[i].p_filesz);
        printf("Header Memory Image Size:\t0x%08x\n", executableHandle->phdr[i].p_memsz);

        puts("-------------------------------------------------------------------------------------");
        printf("\n\n");
    }
    return SUCCESS;
}

int8_t printELF32ProgramHeaders(ELF32_EXECUTABLE_HANDLE_T* executableHandle)
{
    char flags[] = "-------";
    uint32_t phdrSize;

    if(executableHandle->ehdr == NULL || executableHandle->phdr == NULL)
    {
        #ifdef DEBUG
        perror("ERROR NULL pointer in printELF64ProgramHeaders()");
        #endif
        return FAILED;
    }

    if(executableHandle->ehdr->e_phnum == 0 || executableHandle->ehdr->e_phentsize == 0)
    {
        #ifdef DEBUG
        perror("ERROR, NO PHDRS in printELF64ProgramHeaders()");
        #endif
        return FAILED;
    }
    
    phdrSize = (uint32_t)executableHandle->ehdr->e_phentsize;

    for(uint8_t i = 0; i < executableHandle->ehdr->e_phnum; i++)
    {
        printf("Program Header:\t%d\n", i+1);

        dumpHexBytesFromFileHandle(&executableHandle->fileHandle,
            executableHandle->ehdr->e_phoff + (executableHandle->ehdr->e_phentsize * i), sizeof(Elf64_Phdr));
        printf("\n\n");
            
        /* Print the data held in each Phdr in a human readable form. */

        /* First get the program header type. */
        switch(executableHandle->phdr[i].p_type)
        {
            printf("Program Header Type:\t");
            case PT_LOAD:
                printf("PT_LOAD\n");
                break;
            case PT_DYNAMIC:
                printf("PT_DYNAMIC\n");
                break;
            case PT_INTERP: /* This section points to the interpreter. */
                printf("PT_INTERPRETER\n"); /* TODO: Get interpreter. */
                break;
            case PT_NOTE:
                printf("PT_NOTE\n");
                break;
            case PT_PHDR: /* Should only be one of these. */
                printf("PT_LOAD\n"); /* TODO: Confirm there is only one maybe? */
                break;
            case PT_SHLIB:
                printf("PT_SHLIB\n"); /* Not used in standard (could be used for malicious perpuses though. ) */
                break;
            case PT_LOPROC:
                printf("PT_LOPROC\n");
                break; /* LOPROC/HIPROC are processor specific phdrs. */
            case PT_HIPROC:
                printf("PT_HIPROC\n");
                break;
            case PT_GNU_STACK:
                printf("PT_GNU_STACK\n");
                break;
            case PT_NULL:
            default:
                printf("NULL/UNKNOWN\n");
                break;
        }

        switch(executableHandle->phdr[i].p_flags)
        {
            case 1:
                strncpy(flags, "-X-----", PHDR_FLAG_LEN);
                break;
            case 2:
                strncpy(flags, "---W---", PHDR_FLAG_LEN);
                break;
            case 3:
                strncpy(flags, "-X-W---", PHDR_FLAG_LEN);
                break;
            case 4:
                strncpy(flags, "-----R-", PHDR_FLAG_LEN);
                break;
            case 5:
                strncpy(flags, "-X---R-", PHDR_FLAG_LEN);
                break;
            case 6:
                strncpy(flags, "---W-R-", PHDR_FLAG_LEN);
                break;
            case 7:
                strncpy(flags, "-X-W-R-", PHDR_FLAG_LEN);
                break;
        }
        flags[7] = '\0';

        printf("Flags:\t%s\n", flags);
        /* Static offset, seems incorrect. */
        printf("Static Offset:\t0x%08x\n", executableHandle->phdr[i].p_offset);
        printf("Virtual Address:\t0x%08x\n", executableHandle->phdr[i].p_vaddr);
        printf("Physical Address:\t0x%08x\n", executableHandle->phdr[i].p_paddr);

        printf("Header File Image Size:\t0x%08x\n", executableHandle->phdr[i].p_filesz);
        printf("Header Memory Image Size:\t0x%08x\n", executableHandle->phdr[i].p_memsz);

        puts("-------------------------------------------------------------------------------------");
        printf("\n\n");
    }
    return SUCCESS;
}

int8_t printELF64SectionHeaders(ELF64_EXECUTABLE_HANDLE_T* executableHandle)
{
    char flags[SHDR_FLAG_LEN+1];
    uint16_t sectionHeaderSize;
    if(!executableHandle || !executableHandle->phdr)
    {
        #ifdef DEBUG
        perror("NULL Pointer In printELF64SectionHeaders()");
        #endif
        return FAILED;
    }

    if(executableHandle->ehdr->e_shentsize == 0 || executableHandle->ehdr->e_shnum == 0 ||
        executableHandle->ehdr->e_shoff == 0 || executableHandle->ehdr->e_shstrndx == 0)
    {
        printf("%s is stripped.\n", executableHandle->fileHandle.path);
        return SUCCESS;
    }

    sectionHeaderSize = executableHandle->ehdr->e_shentsize;


    for(int i = 0; i < executableHandle->ehdr->e_shnum; i++)
    {
        puts("----------------------------------------------------------\n");
        printf("Section Header:\t%d\n", i+1);

        // dumpHexBytesFromFileHandle(&executableHandle->fileHandle,
        //     executableHandle->ehdr->e_shoff + (executableHandle->ehdr->e_shentsize * i), executableHandle->ehdr->e_shentsize);

        printf("\n\n");
        printf("Section Header String Table Index:\t0x%08x\n", executableHandle->shdr[i].sh_name);

        switch(executableHandle->shdr[i].sh_type)
        {
            printf("Section Header Type:\t");
            case SHT_PROGBITS:
                /* Meaning is defined by the program. 
                 * TODO: Check if I can do anything with this information.
                 */
                printf("PROGBITS\n");
                break;
            case SHT_SYMTAB:
                /* TODO: Print out useful information contained in the symbol table (symbol names and such)
                 * This can be used to dicover call to function in libraries.
                 */
                printf("SYMTAB\n");
                break;
            case SHT_STRTAB:
                /* TODO: Print out all strings contained in the string table. */
                printf("STRTAB\n");
                
                break;
            case SHT_RELA:
                printf("RELA\n");
                break;
            case SHT_HASH:
                printf("HASH TABLE\n");
                break;
            case SHT_DYNAMIC:
                /* TODO; Print GOT info. */
                /* A binary should only have one DYNAMIC section header. */
                printf("DYNAMIC\n");
                break;
            case SHT_NOTE:
                printf("NOTE\n");
                break;
            case SHT_REL:
                printf("REL\n");
                break;
            case SHT_SHLIB:
                printf("SHLIB\n");
                break;
            case SHT_DYNSYM:
                printf("DYNSYM\n");
                break;
            case SHT_LOPROC:
            case SHT_HIPROC:
                printf("LOPROC/HIPROC\n");
                break;
            case SHT_LOUSER:
            case SHT_HIUSER:
                printf("LOUSER/HIUSER\n");
                break;
            case SHT_NOBITS:
                printf("NOBITS\n"); /* May not even be worth printing this out. */
                break;
            case SHT_NULL:
                printf("NULL\n");
                break;
        }
        
        /* Get the flags of the section. */
        switch(executableHandle->shdr[i].sh_flags)
        {
            case 1:
                strncpy(flags, "W-------", SHDR_FLAG_LEN); /* (1 << 0) */
                break;
            case 2:
                strncpy(flags, "-A------", SHDR_FLAG_LEN); /* (1 << 1) */
                break;
            case 3:
                strncpy(flags, "WA------", SHDR_FLAG_LEN);
                break;
            case 4:
                strncpy(flags, "--X-----", SHDR_FLAG_LEN); /* (1 << 2) */
                break;
            case 5:
                strncpy(flags, "W-X-----", SHDR_FLAG_LEN);
                break;
            case 6:
                strncpy(flags, "-AX-----", SHDR_FLAG_LEN);
                break;
            case 16:
                strncpy(flags, "---M----", SHDR_FLAG_LEN); /* (1 << 4) */
                break;
            case 32:
                strncpy(flags, "----S---", SHDR_FLAG_LEN); /* (1 << 5) */
                break;
            case 64:
                strncpy(flags, "-----I--", SHDR_FLAG_LEN); /* (1 << 6) */
                break;
            case 128:
                strncpy(flags, "------P-", SHDR_FLAG_LEN); /* (1 << 7) */
                break;
            case 256:
                strncpy(flags, "-------N", SHDR_FLAG_LEN); /* (1 << 8) */
                break;
            case 0:
            default:
                strncpy(flags, "--------", SHDR_FLAG_LEN); /* NOFLAGS */
                break;
        }
        flags[SHDR_FLAG_LEN] = '\0';
        printf("%s\n", flags);

        printf("SH_ADDR:\t0x%08x\n", executableHandle->shdr[i].sh_addr);
        printf("SH_OFFSET:\t0x%08x\n", executableHandle->shdr[i].sh_offset);
        printf("SH_SIZE:\t0x%08x\n", executableHandle->shdr[i].sh_size);
        printf("SH_ADDRALIGN:\t0x%08x\n", executableHandle->shdr[i].sh_addralign);
        printf("SH_ENTSIZE:\t0x%08x\n", executableHandle->shdr[i].sh_offset);
    }
}


 #ifdef DEBUG

 static void test_isELF()
 {
    assert(isELF("\x7f\x45\x4c\x46\x01") == T_32); // Test a real 32-bit ELF header.
    assert(isELF("\x7f\x45\x4c\x46\x02") == T_64); // Test a real 64-bit ELF header.
    // Test some broken headers
    assert(isELF("\x7f\x45\x4c\x40\x01") == T_NO_ELF);
    assert(isELF("\x7f\x41\x4c\x46\x01") == T_NO_ELF);
    assert(isELF("\x00\x00\x00\x00\x00") == T_NO_ELF);
 }

 static void elf_info_tests()
 {
    test_isELF();
 }

 #endif



#define TEST32 "/home/calum/Test_Files/while32"
#define TEST64 "/home/calum/Test_Files/while64"


