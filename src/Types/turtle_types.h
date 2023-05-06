#ifndef _TURTLE_TYPES_
#define _TURTLE_TYPES_

#include <assert.h>

// #define DEBUG // Used in all .c files for optional debug build that runs tests.
// #define UNITTEST
// #define LOCALTESTFILES // Used for unit tests, enables use of complete path names for files.

#define TRUE             1
#define FALSE            0

/* Definitions of different error values. */
#define ERR_NONE                  0
#define ERR_UNKNOWN               1
#define ERR_NO_MEMORY             2
#define ERR_FORMAT_NOT_SUPPORTED  3
#define ERR_NULL_ARGUMENT         4


#define TRUE_STR         "TRUE"
#define FALSE_STR        "FALSE"

#endif