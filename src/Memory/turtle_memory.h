#ifndef TURTLE_MEMORY
#define TURTLE_MEMORY

#include <sys/mman.h>

#include "../FileOperations/fileOps.h"
#include "../Modules/ELFinfo/elfinfo.h"

int8_t safeAllocateFileHandle(char* filename, FILE_HANDLE_T* fileHandle);

int8_t safeFreeFileHandle(FILE_HANDLE_T* handle);

#endif