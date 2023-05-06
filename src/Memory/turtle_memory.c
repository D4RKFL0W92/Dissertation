#include "./turtle_memory.h"

#define MAX_MAPPED_REGIONS 1024


int8_t safeAllocateFileHandle(char* filename, FILE_HANDLE_T* fileHandle)
{
  size_t len;

  if( (fileHandle->fd = open(filename, O_RDONLY)) == -1)
  {
    perror("ERROR opening file.");
    return ERR_UNKNOWN;
  }

  if(fstat(fileHandle->fd, &fileHandle->st) == -1)
  {
    perror("ERROR stat'ing file.");
    return ERR_UNKNOWN;
  }

  if((fileHandle->p_data = mmap(NULL, fileHandle->st.st_size, PROT_READ, MAP_PRIVATE, fileHandle->fd, 0)) == MAP_FAILED)
  {
    perror("ERROR mapping file to memory.");
    return ERR_UNKNOWN;
  }

  ((len = (strlen(filename)) <= PATH_MAX ) ? len : PATH_MAX);
  strncpy(fileHandle->path, filename, len);

  return ERR_NONE;
}

int8_t safeFreeFileHandle(FILE_HANDLE_T* handle)
{
  if(handle->p_data == NULL)
  {
    return ERR_UNKNOWN;
  }
  if(munmap(handle->p_data, handle->st.st_size) <= 0)
  {
    return ERR_UNKNOWN;
  }

  /* Search for that entry in mappedRegions. */
  return ERR_NONE;
}