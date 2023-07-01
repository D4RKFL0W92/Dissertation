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

#ifndef TURTLE_MEMORY
#define TURTLE_MEMORY

#include <sys/mman.h>

#include "../FileOperations/fileOps.h"
#include "../Modules/ELFinfo/elfinfo.h"

typedef struct MMAPPED_REGIONS
{
    void*  pMem;
    size_t mappingSize;
}MMAPPED_REGIONS_T;

typedef struct MEMORY_TRACKER
{
    MMAPPED_REGIONS_T mappedRegions[1024];
    uint32_t mappedCount;
}MEMORY_TRACKER_T;

int8_t safeAllocateFileHandle(char* filename, FILE_HANDLE_T* fileHandle);

int8_t safeFreeFileHandle(FILE_HANDLE_T* handle);
int8_t safeFreeELF64ExecutableHandle(ELF64_EXECUTABLE_HANDLE_T* executableHandle);

#endif