/*
 * Copywrite: 2023 Calum Dawson calumjamesdawson@gmail.com
*/

#ifndef _ELFTYPES_
#define _ELFTYPES_

#include <elf.h>
#include <sys/reg.h>

#include "../../Types/turtle_types.h"
#include "../../Logging/logging.h"
#include "../../FileOperations/fileOps.h"

enum BITS {T_NO_ELF, T_32, T_64};
enum ENDIANESS {T_NONE, T_LITTLE, T_BIG};

typedef struct user_regs_struct REGS;

typedef struct ELF32_EXECUTABLE
{
    FILE_HANDLE_T             fileHandle;
    Elf32_Ehdr*               ehdr;
    Elf32_Phdr*               phdr;
    Elf32_Shdr*               shdr;
    REGS                      regs;
    pid_t                     pid;
    int8_t                    isExecuting;
}ELF32_EXECUTABLE_HANDLE_T;

typedef struct ELF64_EXECUTABLE
{
    FILE_HANDLE_T           fileHandle;
    Elf64_Ehdr*             ehdr;
    Elf64_Phdr*             phdr;
    Elf64_Shdr*             shdr;
    REGS                    regs;
    pid_t                   pid;
    int8_t                  isExecuting;
}ELF64_EXECUTABLE_HANDLE_T;

typedef union ELF_EXECUTABLE
{
    ELF32_EXECUTABLE_HANDLE_T elfHandle32;
    ELF64_EXECUTABLE_HANDLE_T elfHandle64;
} ELF_EXECUTABLE_T;

#endif