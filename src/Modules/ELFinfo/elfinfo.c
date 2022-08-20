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

uint8_t* mapELFToMemory(char* filepath, enum BITS* arch, uint64_t* map_sz)
{
    #ifdef DEBUG
    char* func_name = "mapELFToMemory()";
    #endif
    ssize_t bytes_read;
    char MAGIC[6];
    uint8_t* file_mem;
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
    
    if( (*arch = isELF(MAGIC)) == T_NO_ELF) // Store the architecture of the binary for use later.
    {
        #ifdef DEBUG
        logEvent(LOG_FILE, func_name, "isELF()");
        perror("File being read is not an ELF file.");
        #endif
        
        return NULL;
    }

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
int printELFPhdrs(uint8_t* p_mem)
{
    enum BITS arch;
    uint64_t file_sz;

    p_mem = mapELFToMemory(TEST_FILE, &arch, &file_sz);

    if(arch == T_64)
    {
        return printELF64Phdrs(p_mem);
    }
    else if(arch == T_32)
    {
        return printELF32Phdrs(p_mem);
    }
    
}

static int printELF64Phdrs(uint8_t* p_mem)
{

    Elf64_Ehdr* ehdr;

    Elf64_Phdr* phdr;

    if(p_mem == NULL)
    {
        return -1;
    }
    ehdr = (Elf64_Ehdr *) p_mem;

    phdr = (Elf64_Phdr *) (p_mem + ehdr->e_phoff);
    uint8_t count = 0;

    for(count; count < ehdr->e_phnum; ++count)
    {
        switch(phdr[count].p_type)
        {
            case PT_LOAD:
                printf("PT_LOAD Section VADDR At:\t0x%08x\n", phdr[count].p_vaddr);
                break;
            case PT_DYNAMIC:
                printf("PT_DYNAMIC Section VADDR At:\t0x%08x\n.", phdr[count].p_vaddr);
                break;
            case PT_INTERP:
                printf("PT_INTERP Section VADDR At:\t0x%08x\n.", phdr[count].p_vaddr);
                break;
            case PT_NOTE:
                printf("PT_NOTE Section VADDR At:\t0x%08x\n.", phdr[count].p_vaddr);
                break;
            case PT_SHLIB:
                printf("PT_SHLIB Section VADDR At:\t0x%08x\n.", phdr[count].p_vaddr);
                break;
            case PT_PHDR:
                printf("PT_PHDR Section VADDR At:\t0x%08x\n.", phdr[count].p_vaddr);
                break;
            case PT_GNU_STACK:
                printf("PT_GNU_STACK Section VADDR At:\t0x%08x\n.", phdr[count].p_vaddr);
                break;
            case PT_NULL: break;
        }
    }
    
}

static int printELF32Phdrs(uint8_t* p_mem)
{

    Elf32_Ehdr* ehdr;

    Elf32_Phdr* phdr;

    if(p_mem == NULL)
    {
        return -1;
    }
    ehdr = (Elf32_Ehdr *) p_mem;

    phdr = (Elf32_Phdr *) (p_mem + ehdr->e_phoff);
    uint8_t count = 0;

    for(count; count < ehdr->e_phnum; ++count)
    {
        switch(phdr[count].p_type)
        {
            case PT_LOAD:
                printf("PT_LOAD Section VADDR At:\t0x%08x\n", phdr[count].p_vaddr);
                break;
            case PT_DYNAMIC:
                printf("PT_DYNAMIC Section VADDR At:\t0x%08x\n.", phdr[count].p_vaddr);
                break;
            case PT_INTERP:
                printf("PT_INTERP Section VADDR At:\t0x%08x\n.", phdr[count].p_vaddr);
                break;
            case PT_NOTE:
                printf("PT_NOTE Section VADDR At:\t0x%08x\n.", phdr[count].p_vaddr);
                break;
            case PT_SHLIB:
                printf("PT_SHLIB Section VADDR At:\t0x%08x\n.", phdr[count].p_vaddr);
                break;
            case PT_PHDR:
                printf("PT_PHDR Section VADDR At:\t0x%08x\n.", phdr[count].p_vaddr);
                break;
            case PT_GNU_STACK:
                printf("PT_GNU_STACK Section VADDR At:\t0x%08x\n.", phdr[count].p_vaddr);
                break;
            case PT_NULL: break;
        }
    }
    
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
            logEvent(TEST_FILE, "printELFInfo()", "fopen()");
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

Elf32_Ehdr* getELFHeader32(int fd)
{
    Elf32_Ehdr* e_hdr;
    char MAGIC[5];
    unsigned char buf[ sizeof(Elf32_Ehdr) ];

    if( read(fd, buf, sizeof(Elf32_Ehdr)) < sizeof(Elf32_Ehdr) )
    {
        return NULL;
    }

    e_hdr = (Elf32_Ehdr *)buf;

    return e_hdr;
}

Elf64_Ehdr* getELFHeader64(int fd)
{
    Elf64_Ehdr* e_hdr;
    char MAGIC[5];
    unsigned char buf[sizeof(Elf64_Ehdr)];

    if(read(fd, buf, sizeof(Elf64_Ehdr)) < sizeof(Elf64_Ehdr))
    {
        return NULL;
    }

    e_hdr = (Elf64_Ehdr *) buf;

    return e_hdr;
}

//  int main(int argc, char** argv)
//  {
//     enum BITS arch;
//     uint64_t file_sz;
//     // printELFInfo(TEST_FILE, NULL);
//     // test_getELF32PhdrAddress();

//     uint8_t* p_mem;

//     p_mem = mapELFToMemory(TEST_FILE, &arch, &file_sz);
//     printELFPhdrs(p_mem);
//     return 1;
//  }

 #ifdef DEBUG

 static void test_isELF()
 {
    assert(isELF("\x7f\x45\x4c\x46\x01") == T_32); // Test a real 64-bit ELF header.
    assert(isELF("\x7f\x45\x4c\x46\x02") == T_64); // Test a real 64-bit ELF header.
    // Test some broken headers
    assert(isELF("\x7f\x45\x4c\x40\x01") == T_NO_ELF);
    assert(isELF("\x7f\x41\x4c\x46\x01") == T_NO_ELF);
    assert(isELF("\x00\x00\x00\x00\x00") == T_NO_ELF);

 }

// static int test_getELF32PhdrAddress()
// {
//     Elf32_Addr phdr_offset;
//     enum BITS bits;
//     uint8_t* p_mem;
//     uint64_t elf_sz;

//     p_mem = mapELFToMemory(TEST_FILE, &bits, &elf_sz);
//     assert(p_mem != NULL);
//     assert(bits == T_32);

//     phdr_offset = getELF32PhdrAddress(p_mem);
//     assert(phdr_offset != 0);
//     printf("Program Header Offset:\t0x%08x\n", phdr_offset);
// }

 #endif
