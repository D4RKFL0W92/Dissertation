#include "elfinfo.h"


 static enum BITS isELF(char* arch)
 {
    if(arch == NULL || strlen(arch) < 5)
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



Elf32_Ehdr* getELFHeader32(char* filepath)
{
    Elf32_Ehdr* e_hdr;
    char MAGIC[5];
    unsigned char buf[sizeof(Elf32_Ehdr)];
    int fd;

    if( (fd = open(filepath, O_RDONLY)) < 0)
    {
        return NULL;
    }

    if(read(fd, buf, sizeof(Elf32_Ehdr)) < sizeof(Elf32_Ehdr))
    {
        return NULL;
    }

    
    strncpy(MAGIC, buf, 5);
    if(!isELF(MAGIC))
    {
        return NULL;
    }

    e_hdr = (Elf32_Ehdr *)buf;
    close(fd);

    return e_hdr;

}

Elf64_Ehdr* getELFHeader64(char* filepath)
{
    Elf64_Ehdr* e_hdr;
    char MAGIC[5];
    unsigned char buf[sizeof(Elf64_Ehdr)];
    int fd;

    if( (fd = open(filepath, O_RDONLY)) < 0)
    {
        return NULL;
    }

    if(read(fd, buf, sizeof(Elf64_Ehdr)) < sizeof(Elf64_Ehdr))
    {
        return NULL;
    }

    
    strncpy(MAGIC, buf, 5);
    if(!isELF(MAGIC))
    {
        return NULL;
    }

    e_hdr = (Elf64_Ehdr *)buf;
    close(fd);

    return e_hdr;
}

int8_t printELF32Strings(char* filepath)
{
    ssize_t bytes_read;
    char MAGIC[5];
    uint8_t* file_mem;
    int fd, ret;
    struct stat st;

    if( (fd = open(filepath, O_RDONLY)) < 0)
    {
        // Should really log errors/failures.
        perror("Unable to open file inside printELF32Strings().");
        return -1;
    }

    if(fstat(fd, &st) < 0)
    {
        perror("Unable to stat() file in printELF32Strings().");
        return -1;
    }

    // Check is an ELF file before mapping into memory.
    if( (bytes_read = read(fd, MAGIC, 5)) < 5)
    {
        perror("Unable to read() ELF header in printELF32Strings().");
        return -1;
    }

    enum BITS arch = isELF(MAGIC);

    switch(arch)
    {
        case T_32:
            /* Map the ELF file into */
            if( (file_mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
            {
                perror("Unable to mmap() file in printELF32Strings().");
                return -1;
            }
            Elf32_Ehdr* ehdr32 = (Elf32_Ehdr *)file_mem[0];

            /* Find and print the strings in the str table .*/

            break;

        case T_64:
            /* Map the ELF file into */
            if( (file_mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
            {
                perror("Unable to mmap() file in printELF32Strings().");
                return -1;
            }
            Elf64_Ehdr* ehdr64 = (Elf64_Ehdr *)file_mem[0];

            /* Find and print the strings in the str table .*/

            break;

        case T_NO_ELF:
            printf("%s is not an ELF file.", filepath);
            return -1;
    }

    
}

 int main(int argc, char** argv)
 {

    // test_isELF();
    // test_getELFHeader64();

    printELF32Strings("/home/calum/Malware_Research/ELF_Parser/test");
    return 1;
 }

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

 static void test_getELFHeader64()
 {
    Elf64_Ehdr* ehdr;
    char *filename = "./test";

    ehdr = getELFHeader64(filename);

    /* Test e_ident array for appropriate values */
    assert(ehdr->e_ident[EI_CLASS] == ELFCLASS64); // Check word size of executable
    assert(ehdr->e_ident[EI_DATA] == ELFDATA2LSB || ehdr->e_ident[EI_DATA] == ELFDATA2MSB || ehdr->e_ident[EI_DATA] == ELFDATANONE); // Check endianess
    assert(ehdr->e_ident[EI_VERSION] == EV_CURRENT || ehdr->e_ident[EI_VERSION] == EV_NONE); // Check version
    assert(ehdr->e_ident[EI_OSABI] == ELFOSABI_NONE || ehdr->e_ident[EI_OSABI] == ELFOSABI_SYSV || ehdr->e_ident[EI_OSABI] == ELFOSABI_HPUX
        || ehdr->e_ident[EI_OSABI] == ELFOSABI_NETBSD || ehdr->e_ident[EI_OSABI] == ELFOSABI_LINUX || ehdr->e_ident[EI_OSABI] == ELFOSABI_SOLARIS
        || ehdr->e_ident[EI_OSABI] == ELFOSABI_IRIX || ehdr->e_ident[EI_OSABI] == ELFOSABI_FREEBSD || ehdr->e_ident[EI_OSABI] == ELFOSABI_TRU64
        || ehdr->e_ident[EI_OSABI] == ELFOSABI_ARM || ehdr->e_ident[EI_OSABI] == ELFOSABI_STANDALONE); // Check ABI
    /* Test e_type for appropriate values. */
    assert(ehdr->e_type == ET_NONE || ehdr->e_type == ET_REL || ehdr->e_type == ET_EXEC || ehdr->e_type == ET_DYN || ehdr->e_type == ET_CORE);
    /* Test e_machine for appropriate values */

    assert(ehdr->e_phoff <= sizeof(Elf64_Ehdr));

 }

 #endif