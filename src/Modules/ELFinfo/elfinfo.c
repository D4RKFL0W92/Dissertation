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

 int main(int argc, char** argv)
 {
    // if(argc < 2)
    // {
    //     puts("Provide path to binary.");
    //     return 0;
    // }

    // int fd;
    // char path[] = "./test";

    // if( (fd = open(path, O_RDONLY)) < 0)
    // {
    //     puts("Failed to open file.");
    //     exit(-1);
    // }

    // char buf[20];
    // if(read(fd, buf, 20) < 10)
    // {
    //     puts("Unable to read from file.");
    //     exit(-1);
    // }

    // enum BITS ret = isELF(buf);
    // if(ret == T_32)
    // {
    //     puts("32 BIT");
    //     Elf32_Ehdr* ehdr;
    // }
    // else if(ret == T_64)
    // {
    //     puts("64 BIT");
    //     Elf64_Ehdr* ehdr;

    //     if( (ehdr = getELFHeader64(path)) == NULL)
    //     {
    //         puts("Unable to get ELF header.");
    //         exit(-1);
    //     }
    //     printf("Entry located at: 0x%x\n", ehdr->e_entry);
    //     printf("Program header located at: 0x%x\n", ehdr->e_phoff);
    // }
    // else
    // {
    //     puts("Unknown architecture.");
    //     Elf64_Ehdr* ehdr;
    // }

    test_isELF();
    test_getELFHeader64();

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