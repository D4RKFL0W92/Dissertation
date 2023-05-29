#ifndef _TURTLE_TYPES_
#define _TURTLE_TYPES_

#include <assert.h>
#include <unistd.h>

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

#define ERR_TRACE_OPERATION_FAILED     35

#define TRUE_STR         "TRUE"
#define FALSE_STR        "FALSE"

#endif