#include "./fileOps.h"

char* basicFileMap(char* filepath, uint64_t* fileSz)
{
    char* file_mem;
    struct stat st;
    int fd;

    if( (fd = open(filepath, O_RDONLY)) == -1)
    {
        perror("ERROR opening file.");
        return NULL;
    }

    if(fstat(fd, &st) == -1)
    {
        perror("ERROR stat'ing file.");
        return NULL;
    }

    if((file_mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    {
        perror("ERROR mapping file to memory.");
        return NULL;
    }

    *fileSz = st.st_size;
    return file_mem;
}

int8_t scanForStrings(char* filepath, uint16_t len)
{
    char strBuff[8192];
    char* p_mem;
    uint64_t sz;
    
    if( (p_mem = basicFileMap(filepath, &sz)) == NULL)
    {
        #ifdef DEBUG
        perror("Error mapping file in scanForStrings()");
        #endif
        logEvent(LOG_FILE, "scanForStrings()", "Unable to map file.");
        return FAILED;
    }

    for(uint64_t i = 0; i < sz; i++)
    {
        uint16_t strLen = 0;

        if((uint8_t *) p_mem[i] > 0x21 && (uint8_t *) p_mem[i] < 0x7E)
        {
            strBuff[strLen++] = p_mem[i++];
            while((uint8_t *) p_mem[i] > 0x21 && (uint8_t *) p_mem[i] < 0x7E)
            {
                strBuff[strLen++] = p_mem[i++];
            }

            if(strLen >= len)
            {
                printf("%s\n", strBuff);
            }

            if(strLen > 0)
            {
                for(uint16_t j = strLen; j > 0; --j)
                {
                    strBuff[j] = '\0';
                }
            }
        }

        
    }

    return SUCCESS;

}