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
#include "../../Logging/logging.h"





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

typedef struct
{
    uint16_t pt_loadCnt;
    uint16_t pt_dynamicCnt;
    uint16_t pt_interpCnt;
    uint16_t pt_noteCnt;
    uint16_t pt_shlibCnt;
    uint16_t pt_phdrCnt;
    uint16_t pt_gnu_stackCnt;
}PHDR_COUNT;


enum BITS {T_NO_ELF, T_32, T_64};
enum ENDIANESS {T_NONE, T_LITTLE, T_BIG};

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

int printELFPhdrs(uint8_t* p_mem);
/*
 * Takes a pointer to an ELF executable that has already been check that it
 * points to a valid ELF file.
*/
static int printELF64Phdrs(uint8_t* p_mem);
static int printELF32Phdrs(uint8_t* p_mem);


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

uint8_t printELF64StringTables(uint8_t* p_mem);

int8_t printELF32Strings(char* filepath);
int8_t printELF64Strings(char* filepath);

#ifdef DEBUG

#define TEST_FILE   "/home/calum/Malware_Research/ELF_Parser/test"
#define TEST_FILE64 "/home/calum/Malware_Research/ELF_Parser/test64"


    static void test_isELF();

    static int test_getELF64PhdrAddress();
    static int test_getELF32PhdrAddress();
    // static void test_getELFHeader32();
    // static void test_getELFHeader64();

#endif


#endif