#include "elfinfo.h"

static int logEvent(char* filepath, const char* func_name, const char* cause)
{
    FILE* file;

    if( (file = fopen(filepath, "a+")) == NULL)
    {
        perror("Unable to log error");
        return -1;
    }

    if(fprintf(file, "%s failed while calling %s", func_name, cause) < 0)
    {
        perror("Unable to write log to file.");
        return -1;
    }

    return 1;
}

static enum BITS isELF(char* arch)
{
    if(arch == NULL || strlen(arch) < 6)
        return T_NO_ELF;

    if(arch[0] != 0x7f || arch[1] != (uint8_t)'E' ||
        arch[2] != (uint8_t)'L' || arch[3] != (uint8_t)'F')
        return T_NO_ELF;

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

    return T_NO_ELF; // // Likely not an ELF executable
}

uint8_t* mapELFToMemory(char* filepath, enum BITS* arch, uint64_t* map_sz)
{
    #ifdef DEBUG
    char* func_name = "mapELFToMemory()";
    #endif
    ssize_t bytes_read;
    char MAGIC[5];
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
    if( (bytes_read = read(fd, MAGIC, 5)) < 5)
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

uint8_t printELFInfo(char* filepath)
{
    #ifdef DEBUG
    const char *func_name = "printELFInfo()";
    #endif

    char ehdr_buf[ sizeof(Elf64_Ehdr) ];
    char MAGIC[6];

    char class[6];
    char endian[6];
    char arch[20];
    
    enum BITS bits;
    int fd;
    ssize_t read_ret;

    if( (fd = open(filepath, O_RDONLY)) < 0)
    {
        #ifdef DEBUG
        perror("Unable to open() file in printELFInfo().");
        #endif

        logEvent(LOG_FILE, func_name, "open()");
        close(fd);
        return FALSE;
    }

    if(read(fd, MAGIC, sizeof(MAGIC)) == -1)
    {
        #ifdef DEBUG
        perror("Unable to read() magic bytes of file in printELFInfo().");
        #endif

        logEvent(LOG_FILE, func_name, "read()");
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
            strncpy(endian, "LITTLE", strlen("LITTLE"));
            break;

        case ELFDATA2MSB:
            strncpy(endian, "BIG", strlen("BIG"));
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
        strncpy(class, "32-BIT", strlen("32-BIT"));
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

        
    }
    else if(bits == T_64)
    {
        strncpy(class, "64-BIT", 6);
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
    }
    else
    {
        close(fd);
        return FALSE;
    }


    printf("\nClass\t%s\nEndianess:\t%s\n", class, endian); // 
    close(fd);
    return TRUE;
}

Elf32_Ehdr* getELFHeader32(int fd)
{
    Elf32_Ehdr* e_hdr;
    char MAGIC[5];
    unsigned char buf[sizeof(Elf32_Ehdr)];

    if(read(fd, buf, sizeof(Elf32_Ehdr)) < sizeof(Elf32_Ehdr))
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

 int main(int argc, char** argv)
 {
    printELFInfo(TEST_FILE);

    return 1;
 }

 #ifdef DEBUG

//  static void test_isELF()
//  {
//     assert(isELF("\x7f\x45\x4c\x46\x01") == T_32); // Test a real 64-bit ELF header.
//     assert(isELF("\x7f\x45\x4c\x46\x02") == T_64); // Test a real 64-bit ELF header.
//     // Test some broken headers
//     assert(isELF("\x7f\x45\x4c\x40\x01") == T_NO_ELF);
//     assert(isELF("\x7f\x41\x4c\x46\x01") == T_NO_ELF);
//     assert(isELF("\x00\x00\x00\x00\x00") == T_NO_ELF);

//  }


 #endif