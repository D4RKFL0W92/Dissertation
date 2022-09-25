#include "./fileOps.h"

uint8_t* basicFileMap(char* filepath, uint64_t* fileSz)
{
    uint8_t* file_mem;
    struct stat st;
    int fd;

    if( (fd = open(filepath, O_RDONLY)) == -1)
    {
        perror("ERROR opening file.");
        return FALSE;
    }

    if(fstat(fd, &st) == -1)
    {
        perror("ERROR stat'ing file.");
        return FALSE;
    }

    if((file_mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    {
        perror("ERROR mapping file to memory.");
        return FALSE;
    }

    return file_mem;
}