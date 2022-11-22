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