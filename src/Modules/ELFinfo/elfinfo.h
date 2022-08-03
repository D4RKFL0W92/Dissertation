#ifndef _ELF_INFO_
#define _ELF_INFO_
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <elf.h>
#include <unistd.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "../../Types/turtle_types.h"

#define DEBUG

#define LOG_FILE "/home/calum/Dissertation_Project/Logs/elfinfo_logs"

enum BITS {T_NO_ELF, T_32, T_64};
enum ENDIANESS {T_NONE, T_LITTLE, T_BIG};

static int logEvent(char* filepath, const char* func_name, const char* cause);

/*
 * Checks the first five bytes of the file to see if they are in accourdance with
 * an ELF file.
 * 
 * Param_1: A five byte string taken from the start of the ELF file.
 * 
 * Return: Returns an enum value, representing the word size of the binary:
 *          T_32, T64, or T_NO_ELF
*/
static enum BITS isELF(char* MAG);

enum ENDIANESS getEndianess(unsigned char);

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
uint8_t* mapELFToMemory(char* filepath, enum BITS* arch, uint64_t* map_sz);

uint8_t printELFInfo(char* filepath);

Elf32_Ehdr* getELFHeader32(int fd);
Elf64_Ehdr* getELFHeader64(int fd);

int8_t printELF32Strings(char* filepath);
int8_t printELF64Strings(char* filepath);

#ifdef DEBUG

#define TEST_FILE "/home/calum/Malware_Research/ELF_Parser/test"


    // static void test_isELF();
    // static void test_getELFHeader32();
    // static void test_getELFHeader64();

#endif


#endif