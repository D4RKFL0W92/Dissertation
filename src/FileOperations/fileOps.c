#include "./fileOps.h"

char* basicFileMap(const char* filepath, uint64_t* fileSz)
{
    char* file_mem;
    struct stat st;
    int fd;

    if(!filepath || !fileSz)
    {
        #ifdef DEBUG
        perror("NULL pointer passed as argument to basicFileMap()");
        #endif
        return NULL;
    }

    if( (fd = open(filepath, O_RDONLY)) == -1)
    {
        #ifdef DEBUG
        perror("ERROR opening file.");
        #endif
        return NULL;
    }

    if(fstat(fd, &st) == -1)
    {
        #ifdef DEBUG
        perror("ERROR stat'ing file.");
        #endif
        goto cleanup;
    }

    if((file_mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    {
        #ifdef DEBUG
        perror("ERROR mapping file to memory.");
        #endif
        goto cleanup;
    }

    close(fd);

    *fileSz = st.st_size;
    return file_mem;

    cleanup:
    {
        close(fd);
        return NULL;
    }
}

int8_t mapFileToStruct(const char* filepath, FILE_HANDLE_T* handle)
{
    if(!filepath || !handle)
    {
        #ifdef DEBUG
        perror("Null pointer passed as parameter in mapFileToStruct()");
        #endif
        return FAILED;
    }
    if( (handle->fd = open(filepath, O_RDONLY)) == -1)
    {
        #ifdef DEBUG
        perror("ERROR opening file.");
        #endif
        return FAILED;
    }

    if(fstat(handle->fd, &handle->st) == -1)
    {
        #ifdef DEBUG
        perror("ERROR stat'ing file.");
        #endif
        goto cleanup;
    }

    if((handle->p_data = mmap(NULL, handle->st.st_size, PROT_READ, MAP_PRIVATE, handle->fd, 0)) == MAP_FAILED)
    {
        #ifdef DEBUG
        perror("ERROR mapping file to memory.");
        #endif
        goto cleanup;
    }

    handle->p_data_seekPtr = handle->p_data;
    strncpy(handle->path, filepath, PATH_MAX);

    return SUCCESS;

    cleanup:
    {
        close(handle->fd);
        return FAILED;
    }
}

int8_t unmapFileFromStruct(FILE_HANDLE_T* handle)
{
    if(handle == NULL)
    {
        #ifdef DEBUG
        perror("NULL handle passed as argument to unmapFileFromStruct()");
        #endif
        return FAILED;
    }
    if(!handle->p_data || handle->st.st_size == 0)
    {
        #ifdef DEBUG
        perror("Non-mapped memory passed to unmapFileFromStruct()");
        #endif
        return FAILED;
    }

    handle->p_data_seekPtr = NULL;
    if(munmap(handle->p_data, handle->st.st_size) == 0)
    {
        return SUCCESS;
    }
    #ifdef DEBUG
    perror("Unable to unmap memory in unmapFileFromStruct()");
    #endif
    return FAILED;
}

uint8_t* sha1File(const char* filepath)
{
    int readAmount;
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
        goto cleanup;
    }

    if( (data = malloc(st.st_size)) == NULL)
    {
        #ifdef DEBUG
        perror("ERROR allocating memory for file read in sha1File()");
        #endif
        goto cleanup;
    }

    if( (hashDigest = malloc(SHA_DIGEST_LENGTH)) == NULL)
    {
        #ifdef DEBUG
        perror("ERROR allocating memory for hash digest in sha1File()");
        #endif
        goto cleanup;
    }

    if( (readAmount = (int)read(fd, data, st.st_size-bytesRead)) < 0)
    {
        #ifdef DEBUG
        perror("ERROR reading from file in sha1File()");
        #endif
        goto cleanup;
    }

    SHA1(data, st.st_size, hashDigest);

    if(hashDigest == NULL)
    {
        #ifdef DEBUG
        perror("ERROR calculating sha1 hash of file in sha1File()");
        #endif
        goto cleanup;
    }

    free(data);
    close(fd);

    return hashDigest;

    cleanup:
    {
        free(hashDigest);
        free(data);
        close(fd);
        return NULL;
    }
}

int8_t printSHA1OfFile(const char* filepath)
{
    uint8_t* messageDigest = NULL;

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

    if(messageDigest)
    {
        free(messageDigest);
    }
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
        /* In the ASCII range (acount for spaces). */
        if((p_mem[i] > 0x21 && p_mem[i] < 0x7E) || p_mem[i] == 0x20)
        {
            strBuff[strLen++] = p_mem[i++];
            while((p_mem[i] > 0x21 && p_mem[i] < 0x7E) || p_mem[i] == 0x20)
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
        printf("Offset exceeds file size."); // Useful feedback to the user.
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
            printf("\n0x%08x ", i);
        }
        ++lineByteCount;
        printf("|%02x ", (uint8_t) handle->p_data[i]);
         /* Reset at end of loop. */
        if(lineByteCount == 0x10)
        {
            lineByteCount = 0;
        }
        
    }
    printf("\n");
    return SUCCESS;
}




/* Unit tests for fileOps.c */
#ifdef UNITTEST
void test_basicFileMap_null_filepath()
{
    uint64_t fileSz = 0;

    char* ret = basicFileMap(NULL, &fileSz);

    assert(ret == NULL);
    assert(fileSz == 0);
}

void test_basicFileMap_null_fileSize()
{
    const char* filepath = "garbage";

    char* ret = basicFileMap(filepath, NULL);

    assert(ret == NULL);
    assert(filepath != NULL);
    assert(strncmp(filepath, "garbage", 7) == 0);
}

#ifdef LOCALTESTFILES
void test_basicFileMap_null_legitimate_file()
{
    const char* filepath = "/home/calum/Dissertation_Project/tests/files/text1.txt";
    uint64_t fileSz = 0;

    char* ret = basicFileMap(filepath, &fileSz);

    assert(ret != NULL);
    assert(strncmp(filepath, "/home/calum/Dissertation_Project/tests/files/text1.txt", 27) == 0);
    assert(fileSz == 11);

    munmap(ret, fileSz);
}
#endif

void test_mapFileToStruct_null_filepath()
{
    FILE_HANDLE_T handle = {0};
    int ret = mapFileToStruct(NULL, &handle);

    assert(ret == FAILED);
    assert(handle.fd == 0);
    assert(handle.p_data == NULL);
    assert(handle.p_data_seekPtr == NULL);
    assert(handle.pathLen == 0);
}

void test_mapFileToStruct_null_filehandle()
{
    const char *filepath = "garbage";
    int ret = mapFileToStruct(filepath, NULL);

    assert(ret == FAILED);
    assert(strncmp(filepath, "garbage", 7) == 0);
}

void fileOpsTestSuite()
{
    /* Include any unit tests in here. */
    test_basicFileMap_null_filepath();
    test_basicFileMap_null_fileSize();
    test_basicFileMap_null_legitimate_file();

    test_mapFileToStruct_null_filepath();
    test_mapFileToStruct_null_filehandle();
}
#endif