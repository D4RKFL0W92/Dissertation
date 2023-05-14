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

typedef struct FILE_HANDLE
{
    int                    fd; /* File Desriptor */
    char       path[PATH_MAX]; /* Path Name Of File */
    char*              p_data; /* Pointer to mapped memory. */
    char*      p_data_seekPtr; /* Pointer to mapped memory. (Used for seeking) */
    uint16_t          pathLen; /* Length Of Path Name. */
    struct stat            st; /* stat struct for file data. */

}FILE_HANDLE_T;

/*
 * Basic file map function, performs no checks on file type.
 * Simply maps a file into memory and returns a pointer to that memory.
 * Also returns the file size in a pointer paramet passed to the function.
 *
 * Param_1: Path to a file the caller want to map.
 * Param_2: A uint64_t pointer to receive the size of the mapped memory
 *          allocated for the file.
 *
 * Return: Returns a char pointer to the mapped memory.
*/
char* basicFileMap(const char* filepath, uint64_t* fileSz);

/*
 * A function to map a given file into a FILE_HANDLE_T structure.
 * The function will take the file and map it, filling the fields of the
 * FILE_HANDLE_T structure in the process.
 *
 * Param_1: Path to a file the caller want to map.
 * Param_2: A pointer to a FILE_HANDLE_T structure that
 *          will hold all relavent data associated with
 *          the mapped file.
 *
 * Return: Returns an error code indicating the success or failure of
 *         the function.
*/
int8_t mapFileToStruct(const char* filepath, FILE_HANDLE_T* handle);

/*
 * A function to safely handle unmapping memory associated with a
 * given file handle, passed as a pointer to the function.
 *
 * Param_1: A pointer to a FILE_HANDLE_T structure.
 *
 * Return: Returns an error code indicating the success or failure of
 *         the function.
*/
int8_t unmapFileFromStruct(FILE_HANDLE_T* handle);

/*
 * A function to hash a file using the SHA1 hashing algorithm.
 *
 * Param_1: A path to a file.
 *
 * Return:  Returns a pointer to the hash digest of the given file, NULL
 *          on failure.
*/
uint8_t* sha1File(const char* filepath);

/* A simple function that prints the SHA1 hash of a given file.
 *
 * Param_1: Path to the file to be hashed.
 *
 * Return:  Returns an error code indicating the success or
 *          failure of the function.
*/
int8_t printSHA1OfFile(const char* filepath);

int8_t scanMemForStrings(char * pMem, uint64_t memLen, uint16_t toFindLen);

/* A simple function that scans a given file for ASCII
 * printable strings.
 *
 * Param_1: Path to the file to be scanned.
 * Param_2: Minimum length of string to print.
 *
 * Return:  Returns an error code indicating the success or
 *          failure of the function.
*/
int8_t scanFileForStrings(char* filepath, uint16_t toFindLen);

/* Dumps a given amount of bytes in hex from a given offset.
 * Prints the bytes and the ASCII representation if there is one.
 *
 * Param_1: A pointer to the start of the memory the caller would like to print.
 * Param_2: The offset from the start of the file/memory block, (Used for printing the address).
 * Param_3: The count of bytes the user would like to dump.
 *
 * Return:  Returns an error code indicating the success or
 *          failure of the function.
*/
int8_t dumpHexBytesFromOffset(uint8_t* pMem, uint64_t startAddress, uint64_t uCount);

/* Dumps a given amount of bytes in hex from a given offset into a file.
 * Prints the bytes and the ASCII representation if there is one.
 *
 * Param_1: Path to file the caller want to dump bytes from.
 * Param_2: The offset from the start of the file/memory block, (Used for printing the address).
 * Param_3: The count of bytes the user would like to dump.
 *
 * Return:  Returns an error code indicating the success or
 *          failure of the function.
*/
int8_t dumpHexBytesFromFile(char* filepath, uint64_t startAddress, uint64_t uCount);

/* Dumps a given amount of bytes in hex from a given offset into a file.
 * Prints the bytes and the ASCII representation if there is one.
 *
 * Param_1: A pointer to an already initialised file handle structure.
 * Param_2: The offset from the start of the file/memory block, (Used for printing the address).
 * Param_3: The count of bytes the user would like to dump.
 *
 * Return:  Returns an error code indicating the success or
 *          failure of the function.
*/
int8_t dumpHexBytesFromFileFromFileHandle(FILE_HANDLE_T* handle, uint64_t startAddress, uint64_t uCount);

#ifdef UNITTEST
void fileOpsTestSuite();
#endif /* UNITTEST */

#endif /* _FILE_OPS_ */