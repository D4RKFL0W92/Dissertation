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

enum BITS {T_NO_ELF, T_32, T_64};
enum ENDIANESS {T_NONE, T_LITTLE, T_BIG};

static enum BITS isELF(char* arch);


enum ENDIANESS getEndianess(unsigned char);


Elf32_Ehdr* getELFHeader32(char* filepath);
Elf64_Ehdr* getELFHeader64(char* filepath);

int8_t printELF32Strings(char* filepath);
int8_t printELF64Strings(char* filepath);

#ifdef DEBUG
    static void test_isELF();
    static void test_getELFHeader32();
    static void test_getELFHeader64();
#endif


#endif