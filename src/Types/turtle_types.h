#ifndef _TURTLE_TYPES_
#define _TURTLE_TYPES_

/*
 * Copywrite: 2023 Calum Dawson calumjamesdawson@gmail.com
*/
#include <assert.h>
#include <unistd.h>
#include <stdint.h>

#define TRUE             1
#define FALSE            0

/* Definitions of different error values. */
#define ERR_NONE                        0
#define ERR_UNKNOWN                     1

#define ERR_FORMAT_NOT_SUPPORTED        3

#define ERR_INVALID_ARGUMENT            5
#define ERR_NULL_ARGUMENT               6

#define ERR_NO_MEMORY                  10
#define ERR_MEMORY_ALLOCATION_FAILED   11

#define ERR_FILE_OPERATION_FAILED      20

#define ERR_PROCESS_OPERATION_FAILED   30
#define ERR_PROCESS_ATTACH_FAILED      31

#define ERR_TRACE_OPERATION_FAILED     35

#define ERR_ILLEGAL_MAPPING_SIZE       40

#define ERR_ELF_BINARY_STRIPPED        50 // NOT a critical error but useful to check for.

#define TRUE_STR         "TRUE"
#define FALSE_STR        "FALSE"

typedef uint8_t BOOL;

#endif