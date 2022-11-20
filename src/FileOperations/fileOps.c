#include "./fileOps.h"

char* basicFileMap(char* filepath, uint64_t* fileSz)
{
    FILE_HANDLE_T handle;
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

uint8_t mapFileToStruct(char* filepath, FILE_HANDLE_T* handle)
{
    size_t len;

    if( (handle->fd = open(filepath, O_RDONLY)) == -1)
    {
        perror("ERROR opening file.");
        return FAILED;
    }

    if(fstat(handle->fd, &handle->st) == -1)
    {
        perror("ERROR stat'ing file.");
        return FAILED;
    }

    if((handle->p_data = mmap(NULL, handle->st.st_size, PROT_READ, MAP_PRIVATE, handle->fd, 0)) == MAP_FAILED)
    {
        perror("ERROR mapping file to memory.");
        return FAILED;
    }

    ((len = (strlen(filepath)) <= PATH_MAX ) ? len : PATH_MAX);
    strncpy(handle->path, filepath, len);

    return SUCCESS;
}

uint8_t* sha1File(char* filepath)
{
    struct stat st;
    uint8_t* hashDigest = NULL;
    char* data;
    int fd;
    uint64_t bytesRead = 0;

    if( (fd = open(filepath, O_RDONLY)) == FAILED)
    {
        #ifdef DEBUG
        perror("ERROR opening file in sha1File()");
        #endif
        return NULL;
    }

    if( (fstat(fd, &st)) == FAILED)
    {
        #ifdef DEBUG
        perror("ERROR caling fstat in sah1File()");
        #endif
        return NULL;
    }

    if( (data = malloc(st.st_size)) == NULL)
    {
        #ifdef DEBUG
        perror("ERROR allocating memory for file read in sha1File()");
        #endif
        return NULL;
    }

    /* Store position of data pointer for free'ing later */
    void* p_data = &data;

    if( (hashDigest = malloc(SHA_DIGEST_LENGTH)) == NULL)
    {
        #ifdef DEBUG
        perror("ERROR allocating memory for hash digest in sha1File()");
        #endif
        return NULL;
    }

    // while(bytesRead < st.st_size)
    // {
    //     int readAmount;
    //     if( (readAmount = (int)read(fd, data, st.st_size-bytesRead)) < 0)
    //     {
    //         #ifdef DEBUG
    //         perror("ERROR reading from file in sha1File()");
    //         #endif
    //         return NULL;
    //     }
    //     bytesRead += readAmount;
    //     data += bytesRead;
    // }
    int readAmount;
    if( (readAmount = (int)read(fd, data, st.st_size-bytesRead)) < 0)
    {
        #ifdef DEBUG
        perror("ERROR reading from file in sha1File()");
        #endif
        return NULL;
    }

    SHA1(data, st.st_size, hashDigest);

    if(hashDigest == NULL)
    {
        #ifdef DEBUG
        perror("ERROR calculating sha1 hash of file in sha1File()");
        #endif
        return NULL;
    }

    free(data);
    close(fd);

    return hashDigest;
}

int8_t printSHA1OfFile(char* filepath)
{
    uint8_t* messageDigest;

    if( (messageDigest = sha1File(filepath)) == NULL)
    {
        #ifdef DEBUG
        perror("ERROR calculating sha1 of file in printSHA1OfFile()");
        #endif
        return FAILED;
    }
    printf("SHA1: ");
    for(int i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        printf("%02x", messageDigest[i]);
    }
    printf("\n");

    free(messageDigest);
    return SUCCESS;
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

int8_t dumpHexBytes(char* filepath, uint64_t startAddress, uint64_t uCount)
{
    uint8_t *p_memStart, *p_mem;
    uint64_t sz;

    if( (p_mem = p_memStart = (uint8_t *) basicFileMap(filepath, &sz)) == NULL)
    {
        #ifdef DEBUG
        perror("ERROR mapping file in dumpHexBytes()");
        #endif
        return FAILED;
    }

    if(startAddress > sz || startAddress + uCount > sz)
    {
        #ifdef DEBUG
        perror("ERROR, illegal offset, in dumpHexBytes()");
        #endif
        printf("Offset exceeds file size.");
        return FAILED;
    }

    uint8_t lineByteCount = 0;
    printf("           |00 |01 |02 |03 |04 |05 |06 |07 |08 |09 |0A |0B |0C |0D |0E |0F\n");
    printf("--------------------------------------------------------------------------");
    for(uint64_t i = startAddress; i < (startAddress + uCount); ++i)
    {
        if(lineByteCount == 0)
        {
            printf("\n0x%08x ", startAddress + i);
        }
        ++lineByteCount;
        printf("|%02x ", p_mem[startAddress + i]);
         /* Reset at end of loop. */
        if(lineByteCount == 0x10)
        {
            lineByteCount = 0;
        }
        
    }
    printf("\n");
    return SUCCESS;
}

int8_t dumpHexBytesFromFileHandle(FILE_HANDLE_T* handle, uint64_t startAddress, uint64_t uCount)
{
    uint8_t *pMem;
    uint64_t sz;

    if(handle == NULL || handle->p_data == NULL)
    {
        #ifdef DEBUG
        perror("ERROR, NULL data, in dumpHexBytes()");
        #endif
        return FAILED;
    }

    pMem = handle->p_data;

    if(startAddress > handle->st.st_size || startAddress + uCount > handle->st.st_size)
    {
        #ifdef DEBUG
        perror("ERROR, illegal offset, in dumpHexBytes()");
        #endif
        printf("Offset exceeds file size.");
        return FAILED;
    }

    uint8_t lineByteCount = 0;
    printf("           |00 |01 |02 |03 |04 |05 |06 |07 |08 |09 |0A |0B |0C |0D |0E |0F\n");
    printf("--------------------------------------------------------------------------");
    for(uint64_t i = startAddress; i < (startAddress + uCount); ++i)
    {
        if(lineByteCount == 0)
        {
            printf("\n0x%08x ", startAddress + i);
        }
        ++lineByteCount;
        printf("|%02x ", pMem[startAddress + i]);
         /* Reset at end of loop. */
        if(lineByteCount == 0x10)
        {
            lineByteCount = 0;
        }
        
    }
    printf("\n");
    return SUCCESS;
}