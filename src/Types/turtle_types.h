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

#ifndef _TURTLE_TYPES_
#define _TURTLE_TYPES_

#include <assert.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

#define TRUE             1
#define FALSE            0

/* Definitions of different error values. */
#define ERR_NONE                          0
#define ERR_UNKNOWN                       1

#define ERR_FORMAT_NOT_SUPPORTED          3

#define ERR_INVALID_ARGUMENT              5
#define ERR_NULL_ARGUMENT                 6

#define ERR_NO_MEMORY                    10
#define ERR_MEMORY_ALLOCATION_FAILED     11

#define ERR_FILE_OPERATION_FAILED        20
#define ERR_DIRECTORY_OPERATION_FAILED   21

// Used for when a checked value does not match any
// of it's expected values included in its definition.
#define ERR_UNKNOWN_EXPECTED_VALUE       25

#define ERR_PROCESS_OPERATION_FAILED     30
#define ERR_PROCESS_ATTACH_FAILED        31
#define ERR_PROCESS_MEMORY_READ_FAILED   32

#define ERR_TRACE_OPERATION_FAILED       35

#define ERR_ILLEGAL_MAPPING_SIZE         40

#define ERR_ELF_BINARY_STRIPPED          50 // NOT a critical error but useful to check for.


#define ERR_NULL_VALUE_READ_FROM_MEMORY 100

#define TRUE_STR         "TRUE"
#define FALSE_STR        "FALSE"

typedef uint8_t BOOL;

#endif