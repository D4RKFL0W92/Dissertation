/*
 * Copywrite: 2023 Calum Dawson calumjamesdawson@gmail.com
*/
#ifndef _ELF_INFO_
#define _ELF_INFO_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <elf.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <unistd.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "../../Types/turtle_types.h"
#include "../../Logging/logging.h"
#include "../../FileOperations/fileOps.h"
#include "../IO/io.h"
#include "../Dynamic/elfdynamic.h"
#include "../Headers/elftypes.h"
#include "../../Memory/tvector.h"


#define CLASS32           "32"
#define CLASS64           "64"

#define ENDIAN_LITTLE     "Little"
#define ENDIAN_BIG        "BIG"

#define ELF_REL_T         "Relocatable"
#define ELF_EXEC_T        "Executable"
#define ELF_DYN_T         "Shared Object"
#define ELF_CORE_T        "Core"
#define ELF_UNKNOWN_T     "Unidentifiable"

#define ARCH_AMD          "AMD"
#define ARCH_ARM          "ARM"
#define ARCH_Intel86      "X_86"
#define ARCH_Intel64      "X_64"

#define PHDR_FLAG_LEN       7
#define SHDR_FLAG_LEN      15

#define MIN_ELF32_ENTRY     0x8048000 // Is this correct??

/*
 * Checks the first five bytes of the file to see if they are in accourdance with
 * an ELF file.
 * 
 * Param_1: A five byte string taken from the start of the ELF file.
 * 
 * Return: Returns an enum value, representing the word size of the binary:
 *          T_32, T64, or T_NO_ELF
*/
enum BITS isELF(char* MAG);


/*
 * Tries to open the file specified by 'filepath' and map it to memory. 
 * Thyis function will only map the file to memory if it is an ELF executable file.
 * 
 * Param_1: A string representing a valid path to an ELF file.
 * Param_2: A pointer 'BITS' enum value to receive/store the detected
 *          architecture of the binary.
 * Param_3: a pointer to a uint64_t pointer to receive and store the size of the executable file.
 * 
 * Return: Function returns a pointer to the memory where the file has been mapped.
*/
char* mapELFToMemory(const char* filepath, enum BITS* arch, uint64_t* map_sz);

int8_t mapELF32ToHandleFromFileHandle(FILE_HANDLE_T* fileHandle, ELF32_EXECUTABLE_HANDLE_T** elfHandle);
int8_t mapELF64ToHandleFromFileHandle(FILE_HANDLE_T* fileHandle, ELF64_EXECUTABLE_HANDLE_T** elfHandle);

/*
 * Checks for active PID with same value as given, if one is found it will be mapped
 * to the union type ELF_EXECUTABLE_T that can be later checked for architecture.
 * */
int8_t mapELFToHandleFromPID(char* pidStr, ELF_EXECUTABLE_T ** elfHandle, enum BITS * pArch);


uint64_t getELFEntryFromFile(char* filepath);

/*
 * Prints information relevant to static analysis of the binary ELF file.
 * Capable of handling 32 and 64 bit ELF files.
 * All data is read from the file given by the file path and can be optionally written
 * out to a file given by output_filepath. If NULL is passed as the second argument the
 * output will be written to stdout.

 * Param_1: Pathname to the ELF binary.
 * Param_2: Pathname to optional output file, or NULL

 * Return: Returns TRUE (1) on success or FALSE (0) on failure.
*/
uint8_t printELFInfo(const char* elf_filepath, const char* output_filepath);

/* TODO: Write a functional test for the print functions, unit tests will not be realistic. */
int8_t printElfInfoVerbose(FILE_HANDLE_T* handle);

int8_t printElfEHeader(ELF_EXECUTABLE_T * elfHandle);

int8_t printELFProgramHeaders(ELF_EXECUTABLE_T * elfHandle);

int8_t printELFSectionHeaders(ELF_EXECUTABLE_T * elfHandle);

int8_t printElfStringTable(ELF_EXECUTABLE_T * elfHandle);

uint64_t lookupSymbolAddress(ELF_EXECUTABLE_T * elfHandle, char* symbolName);

/* 
 * Definitions for which function symbol names to print. 
 * Definitions used to dictate which symbols are printed
 * with printSymbolTableData
*/
#define LOCAL   0
#define IMPORTS 1
#define ALL     2
int8_t printSymbolTableData(ELF_EXECUTABLE_T * elfHandle, uint8_t printImports);

#ifdef UNITTEST
void elfInfoTestSuite();
#endif /* UNITTEST */

#endif /* _ELF_INFO_ */
