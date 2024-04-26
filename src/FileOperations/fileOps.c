/*
 * Copyright (c) [2023], Calum Dawson
 * All rights reserved.
 * This code is the exclusive property of Calum Dawson.
 * Any unauthorized use or reproduction without the explicit
 * permission of Calum Dawson is strictly prohibited.
 * Unauthorized copying of this file, via any medium, is
 * strictly prohibited.
 * Proprietary and confidential.
 * Written by Calum Dawson calumjamesdawson@gmail.com, [2023].
*/

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
    return ERR_NULL_ARGUMENT;
  }
  if(!handle->p_data || handle->st.st_size == 0)
  {
    #ifdef DEBUG
    perror("Non-mapped memory passed to unmapFileFromStruct()");
    #endif
    return ERR_INVALID_ARGUMENT;
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

uint8_t* sha256File(const char* filepath)
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

  if( (hashDigest = malloc(SHA256_DIGEST_LENGTH)) == NULL)
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

  SHA256(data, st.st_size, hashDigest);

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

int8_t printSHA256OfFile(const char* filepath)
{
  uint8_t* messageDigest = NULL;

  if( (messageDigest = sha256File(filepath)) == NULL)
  {
    #ifdef DEBUG
    perror("ERROR calculating sha1 of file in printSHA1OfFile()");
    #endif
    return ERR_UNKNOWN;
  }
  printf("SHA256: ");
  for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
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

int8_t scanMemForStrings(char * pMem, uint64_t memLen, uint16_t toFindLen, TVector * vector)
{
  char strBuff[8192] = {0};

  if(pMem == NULL)
  {
    #ifndef DEBUG
    perror("NULL Ptr Passed To scanMemForStrings().");
    #endif
    return  ERR_NULL_ARGUMENT;
  }

  if(memLen == 0)
  {
    #ifndef DEBUG
    perror("Invalid Memory Length Passed To scanMemForStrings().");
    #endif
    return  ERR_NULL_ARGUMENT;
  }

  if(toFindLen <= 1) // Would pick up every ASCII representable byte otherwise.
  {
    #ifndef DEBUG
    perror("Invalid Memory Length Passed To scanMemForStrings().");
    #endif
    return  ERR_NULL_ARGUMENT;
  }

  for(uint64_t i = 0; i < memLen; i++)
  {
    uint16_t strLen = 0;
    /* In the ASCII range (acount for spaces). */
    if((pMem[i] > 0x21 && pMem[i] < 0x7E) || pMem[i] == 0x20)
    {
      strBuff[strLen++] = pMem[i++];
      while((pMem[i] > 0x21 && pMem[i] < 0x7E) || pMem[i] == 0x20)
      {
        strBuff[strLen++] = pMem[i++];
      }

      if(strLen >= toFindLen)
      {
        printf("%s\n", strBuff);
        if(vector != NULL)
        {
          TVector_addElement(vector, strBuff);
        }
      }

      // if(strLen > 0)
      // {
      //   for(uint16_t j = strLen; j > 0; --j)
      //   {
      //     strBuff[j] = '\0';
      //   }
      // }

    }   
  }
  return ERR_NONE;
}

int8_t scanFileForStrings(char* filepath, uint16_t toFindLen, TVector * vector)
{
  char* p_mem;
  uint64_t sz;
  int8_t err = ERR_NONE;

  if( (p_mem = basicFileMap(filepath, &sz)) == NULL)
  {
    #ifdef DEBUG
    perror("Error mapping file in scanFileForStrings()");
    #endif
    return ERR_UNKNOWN;
  }

  err = scanMemForStrings(p_mem, sz, toFindLen, vector);
  close(filepath);

  return err;
}

int8_t dumpHexBytesFromOffset(uint8_t * pMem, uint64_t offsetIntoMemory, uint64_t uCount)
{
  size_t counter = 0;
  int8_t err = ERR_NONE;

  if(pMem == NULL)
  {
    #ifdef DEBUG
    perror("Argument pMem NULL in dumpHexBytesFromOffset()");
    #endif
    return ERR_NULL_ARGUMENT;
  }
  if(uCount == 0)
  {
    #ifdef DEBUG
    perror("Argument uCount is zero in dumpHexBytesFromOffset()");
    #endif
    return ERR_INVALID_ARGUMENT;
  }

  printf("                   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n");
  printf("-------------------------------------------------------------------------------------\n");

  // Print content
  size_t offset = 0;
  while (offset < uCount)
  {
    // Print offset
    printf("0x%016X ", offsetIntoMemory);

    // Print hexadecimal bytes
    for (size_t i = 0; i <= 0x0F; ++i)
    {
      if (offset + i < uCount)
      {
          printf("%02X ", pMem[offset + i]);
      }
      else
      {
        printf("   ");  // Padding for the last line
      }
    }

    // Print ASCII representation
    printf("|");

    for (counter = 0; counter <= 0x0F && offset + counter < uCount; ++counter)
    {
      printf("%c", (pMem[offset + counter] >= 0x20 && pMem[offset + counter] <= 0x7E) ? pMem[offset + counter] : '.');
    }
    if(counter <= 16)
    {
      for(counter; counter <= 0x0F; ++counter)
      {
        printf(".");
      }
    }

    printf("|\n");

    offsetIntoMemory += 16;
    offset += 16;
  }
  return err;
}

int8_t dumpHexBytesFromFile(char* filepath, uint64_t startAddress, uint64_t uCount)
{
  uint8_t *p_mem;
  uint64_t sz;
  int8_t err = ERR_NONE;

  if( (p_mem = (uint8_t *) basicFileMap(filepath, &sz)) == NULL)
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

  err = dumpHexBytesFromOffset(p_mem, startAddress, uCount);
  if(err != ERR_NONE)
  {
    return err;
  }
  return ERR_NONE;
}

int8_t dumpHexBytesFromFileFromFileHandle(FILE_HANDLE_T* handle, uint64_t startAddress, uint64_t uCount)
{
  uint8_t *pMem;
  uint64_t sz;
  int8_t err = ERR_NONE;

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

  err = dumpHexBytesFromOffset(&handle->p_data[startAddress], startAddress, uCount);
  return err;
}




/*
 * Unit tests for fileOps.c
 * This will be part of the automated testing subsystem.
 * Optionally included with the -DUNITTEST build flag.
 */
#ifdef UNITTEST
static void test_basicFileMap_null_filepath()
{
  uint64_t fileSz = 0;

  char* ret = basicFileMap(NULL, &fileSz);

  assert(ret == NULL);
  assert(fileSz == 0);
}

static void test_basicFileMap_null_fileSize()
{
  const char* filepath = "garbage";

  char* ret = basicFileMap(filepath, NULL);

  assert(ret == NULL);
  assert(filepath != NULL);
  assert(strncmp(filepath, "garbage", 7) == 0);
}

static void test_mapFileToStruct_null_filepath()
{
  FILE_HANDLE_T handle = {0};
  int ret = mapFileToStruct(NULL, &handle);

  assert(ret == ERR_UNKNOWN);
  assert(handle.fd == 0);
  assert(handle.p_data == NULL);
  assert(handle.p_data_seekPtr == NULL);
  assert(handle.pathLen == 0);
}

static void test_mapFileToStruct_null_filehandle()
{
  const char *filepath = "garbage";
  int ret = mapFileToStruct(filepath, NULL);

  assert(ret == ERR_UNKNOWN);
  assert(strncmp(filepath, "garbage", 7) == 0);
}

static void test_unmapFileFromStruct_nullFileStruct()
{
  int8_t err = ERR_NONE;

  err = unmapFileFromStruct(NULL);
  assert(err == ERR_NULL_ARGUMENT);
}

static void test_unmapFileFromStruct_invalidFileStruct()
{
  FILE_HANDLE_T fHandle = {0};
  int8_t err = ERR_NONE;

  err = unmapFileFromStruct(&fHandle);
  assert(err == ERR_INVALID_ARGUMENT);
}

static void test_dumpHexBytesFromOffset_legitimateUsage()
{
  uint8_t buff[] = {0x5f, 0x5f, 0x6c, 0x69, 0x62, 0x63, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x5f, 0x6d, 0x61, 0x69};
  int8_t err = ERR_NONE;

  err = dumpHexBytesFromOffset(buff, 0, 10);
  assert(err == ERR_NONE);

  err = dumpHexBytesFromOffset(&buff[5], 5, 10);
  assert(err == ERR_NONE);
}

static void test_dumpHexBytesFromOffset_zeroCount()
{
  uint8_t buff[] = {0x5f, 0x5f, 0x6c, 0x69, 0x62, 0x63, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x5f, 0x6d, 0x61, 0x69};
  int8_t err = ERR_NONE;

  err = dumpHexBytesFromOffset(buff, 0, 0);
  assert(err == ERR_INVALID_ARGUMENT);
}

static void test_dumpHexBytesFromOffset_nullMemoryPointer()
{
  int8_t err = ERR_NONE;

  err = dumpHexBytesFromOffset(NULL, 0, 0);
  assert(err == ERR_NULL_ARGUMENT);
}

void fileOpsTestSuite()
{
  /* Include any unit tests in here. */
  test_basicFileMap_null_filepath();
  test_basicFileMap_null_fileSize();

  test_mapFileToStruct_null_filepath();
  test_mapFileToStruct_null_filehandle();

  test_unmapFileFromStruct_nullFileStruct();
  test_unmapFileFromStruct_invalidFileStruct();

  test_dumpHexBytesFromOffset_legitimateUsage();
  test_dumpHexBytesFromOffset_zeroCount();
  test_dumpHexBytesFromOffset_nullMemoryPointer();

}
#endif /*UNITTEST */