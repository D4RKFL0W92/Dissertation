#ifndef _FILE_OPS_
#define _FILE_OPS_

#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <openssl/sha.h>
#include "../Types/turtle_types.h"
#include "../Logging/logging.h"

/*
 * Basic file map function, performs no checks on file type.
*/
char* basicFileMap(char* filepath, uint64_t* fileSz);
uint8_t* sha1File(char* filepath);
int8_t printSHA1OfFile(char* filepath);

int8_t scanForStrings(char* filepath, uint16_t len);



#endif