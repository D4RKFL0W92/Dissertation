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
    return ERR_UNKNOWN;
  }
  if( (handle->fd = open(filepath, O_RDONLY)) == -1)
  {
    #ifdef DEBUG
    perror("ERROR opening file.");
    #endif
    return ERR_UNKNOWN;
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

  return ERR_NONE;

  cleanup:
  {
    close(handle->fd);
    return ERR_UNKNOWN;
  }
}

int8_t unmapFileFromStruct(FILE_HANDLE_T* handle)
{
  if(handle == NULL)
  {
    #ifdef DEBUG
    perror("NULL handle passed as argument to unmapFileFromStruct()");
    #endif
    return ERR_UNKNOWN;
  }
  if(!handle->p_data || handle->st.st_size == 0)
  {
    #ifdef DEBUG
    perror("Non-mapped memory passed to unmapFileFromStruct()");
    #endif
    return ERR_UNKNOWN;
  }

  handle->p_data_seekPtr = NULL;
  if(munmap(handle->p_data, handle->st.st_size) == 0)
  {
    handle->p_data = NULL;
    if(close(handle->fd) != 0)
    {
      return ERR_FILE_OPERATION_FAILED;
    }
    return ERR_NONE;
  }
  #ifdef DEBUG
  perror("Unable to unmap memory in unmapFileFromStruct()");
  #endif
  return ERR_UNKNOWN;
}

uint8_t* sha1File(const char* filepath)
{
  int readAmount;
  struct stat st;
  uint8_t* hashDigest = NULL;
  char* data;
  int fd;
  uint64_t bytesRead = 0;

  if( (fd = open(filepath, O_RDONLY)) == ERR_UNKNOWN)
  {
    #ifdef DEBUG
    perror("ERROR opening file in sha1File()");
    #endif
    return NULL;
  }

  if( (fstat(fd, &st)) == ERR_UNKNOWN)
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
    return ERR_UNKNOWN;
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
  return ERR_NONE;
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
    return ERR_UNKNOWN;
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
  return ERR_NONE;
}

int8_t dumpHexBytesFromOffset(uint8_t* pMem, uint64_t startAddress, uint64_t uCount)
{
  // TODO: Refactor the printing of hex bytes into this function.
}

int8_t dumpHexBytesFromFile(char* filepath, uint64_t startAddress, uint64_t uCount)
{
  uint8_t *p_memStart, *p_mem;
  uint64_t sz;

  if( (p_mem = p_memStart = (uint8_t *) basicFileMap(filepath, &sz)) == NULL)
  {
    #ifdef DEBUG
    perror("ERROR mapping file in dumpHexBytesFromFile()");
    #endif
    return ERR_UNKNOWN;
  }

  if(startAddress > sz || startAddress + uCount > sz)
  {
    #ifdef DEBUG
    perror("ERROR, illegal offset, in dumpHexBytesFromFile()");
    #endif
    printf("Offset exceeds file size."); // Useful feedback to the user.
    return ERR_UNKNOWN;
  }

  uint64_t counter = 0;
  uint64_t currOffset = 0;
  printf("         00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n");
  printf("--------------------------------------------------------\n");
  
  char buff[16];
  while(counter < (startAddress + uCount))
  {
    memset(buff, 0, sizeof(buff));
    uint8_t i = 0;

    while(i < 0x10) // Write upto 16 bytes into the buffer at both end.
    {
      buff[i] = p_mem[counter];
      counter++;
      i++;
    }

    for(int a = 0; a < 2; a++)
    {
      for(int b = 0; b < 0x10; b++)
      {
        if(a == 0)
        {
          uint8_t byte = buff[b];
          if(b == 0)
          {
            printf("%08x ", startAddress + currOffset);
          }
          printf("%02x ", byte);
          if(b == 0xF)
          {
            printf(" ");
          }
        }
        else
        {
          if(b == 0)
          {
            printf("|");
          }

          if(buff[b] >= 33 && buff[b] <= 126)
          {
            // Check if it's a printable character.
            printf("%c", buff[b]);

          }
          else
          {
            printf(".");
          }

          if(b == 0xF)
          {
            printf("|\n");
          }
        }
      }
    }
    currOffset += 0x10;
  }
  
  return ERR_NONE;
}

int8_t dumpHexBytesFromFileFromFileHandle(FILE_HANDLE_T* handle, uint64_t startAddress, uint64_t uCount)
{
  uint8_t *pMem;
  uint64_t sz;

  if(handle == NULL || handle->p_data == NULL)
  {
    #ifdef DEBUG
    perror("ERROR, NULL data, in dumpHexBytesFromFile()");
    #endif
    return ERR_UNKNOWN;
  }

  if(startAddress > handle->st.st_size || startAddress + uCount > handle->st.st_size)
  {
    #ifdef DEBUG
    perror("ERROR, illegal offset, in dumpHexBytesFromFile()");
    #endif
    printf("Offset exceeds file size.");
    return ERR_UNKNOWN;
  }

  uint8_t lineByteCount = 0;
  printf("       |00 |01 |02 |03 |04 |05 |06 |07 |08 |09 |0A |0B |0C |0D |0E |0F\n");
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
  return ERR_NONE;
}




/*
 * Unit tests for fileOps.c
 * This will be part of the automated testing subsystem.
 * Optionally included with the UNITTEST and LOCALTESTFILES
 * macros located in turtle_types.h
 */
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

void test_mapFileToStruct_null_filepath()
{
  FILE_HANDLE_T handle = {0};
  int ret = mapFileToStruct(NULL, &handle);

  assert(ret == ERR_UNKNOWN);
  assert(handle.fd == 0);
  assert(handle.p_data == NULL);
  assert(handle.p_data_seekPtr == NULL);
  assert(handle.pathLen == 0);
}

void test_mapFileToStruct_null_filehandle()
{
  const char *filepath = "garbage";
  int ret = mapFileToStruct(filepath, NULL);

  assert(ret == ERR_UNKNOWN);
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

void test_mapFileToStruct_legitimate_parameters()
{
  const char *pathname = "/home/calum/Dissertation_Project/tests/files/text1.txt";
  FILE_HANDLE_T handle = {0};
  int ret = mapFileToStruct(pathname, &handle);

  assert(ret == ERR_NONE);
  assert(handle.fd > 0);
  assert(handle.p_data != NULL);
  assert(handle.p_data_seekPtr != NULL);
  assert(handle.st.st_size == 11);

  munmap(handle.p_data, handle.st.st_size);
}

void test_sha1File_correctBehaivour()
{
  const char *pathname = "/home/calum/Dissertation_Project/tests/files/text1.txt";
  /* The SHA1 hash produced by sha1sum of the above file. */
  const char *actualHash = "\xe9\x3c\xea\xc6\xfa\xc2\x08\x85\x98\x7a\xd2\xe8\x69\xd1\x6a\xf6\x23\xf6\x16\x99";
  uint8_t* digest = NULL;
  digest = sha1File(pathname);

  for(int i = 0; i < SHA_DIGEST_LENGTH; i++)
  {
    assert((char)actualHash[i] == (char)digest[i]);
  }

  if(digest == NULL)
  {
    free(digest);
  }
}

void test_unmapFileFromStruct()
{
  FILE_HANDLE_T fileHandle;
  const char *pathname = "/home/calum/Dissertation_Project/tests/files/text1.txt";

  int ret = mapFileToStruct(pathname, &fileHandle);
  
  assert(ret == ERR_NONE);

  unmapFileFromStruct(&fileHandle);

  assert(fileHandle.p_data == NULL);
  assert(fileHandle.p_data_seekPtr == NULL);
}

#endif

void fileOpsTestSuite()
{
  /* Include any unit tests in here. */
  test_basicFileMap_null_filepath();
  test_basicFileMap_null_fileSize();

  test_mapFileToStruct_null_filepath();
  test_mapFileToStruct_null_filehandle();

  /* Tests that a reliant on local test files using complete paths. */
  #ifdef LOCALTESTFILES
  test_basicFileMap_null_legitimate_file();
  test_mapFileToStruct_legitimate_parameters();
  test_sha1File_correctBehaivour();
  test_unmapFileFromStruct();
  #endif
}
#endif