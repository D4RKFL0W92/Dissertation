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

#ifndef IO
#define IO

#include <ctype.h>
#include <math.h>
#include "../ELFinfo/elfinfo.h"
#include "../../Types/turtle_types.h"

BOOL isHexadecimalCharacter(char digit);
uint8_t hexToDecimal(const char* hexString, uint64_t * value);
uint8_t stringToInteger(const char* numString, uint64_t* value);

#ifdef UNITTEST
void ioTestSuite();
#endif

#endif /* IO */