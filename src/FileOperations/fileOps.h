#ifndef _FILE_OPS_
#define _FILE_OPS_

#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <linux/limits.h>
#include <openssl/sha.h>
#include "../Types/turtle_types.h"
#include "../Logging/logging.h"

/* TODO: Write a function to free p_data and close fd of this structure. */
typedef struct FILE_HANDLE
{
    int                    fd;
    char       path[PATH_MAX];
    char*              p_data;
    char*      p_data_seekPtr;
    uint16_t          pathLen;
    struct stat            st;

}FILE_HANDLE_T;

/*
 * Basic file map function, performs no checks on file type.
*/
char* basicFileMap(const char* filepath, uint64_t* fileSz);
int8_t mapFileToStruct(char* filepath, FILE_HANDLE_T* handle);
int8_t unmapFileFromStruct(FILE_HANDLE_T* handle);

uint8_t* sha1File(const char* filepath);
int8_t printSHA1OfFile(const char* filepath);

int8_t scanForStrings(char* filepath, uint16_t len);
int8_t dumpHexBytes(char* filepath, uint64_t startAddress, uint64_t uCount);
int8_t dumpHexBytesFromFileHandle(FILE_HANDLE_T* handle, uint64_t startAddress, uint64_t uCount);


#endif