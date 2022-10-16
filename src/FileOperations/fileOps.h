#ifndef _FILE_OPS_
#define _FILE_OPS_

#include <stdint.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "../Types/turtle_types.h"
#include "../Logging/logging.h"

/*
 * Basic file map function, performs no checks on file type.
*/
char* basicFileMap(char* filepath, uint64_t* fileSz);

int8_t scanForStrings(char* filepath, uint16_t len);


#endif