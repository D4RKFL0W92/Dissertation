#ifndef IO
#define IO

#include <ctype.h>
#include <math.h>
#include "../ELFinfo/elfinfo.h"
#include "../../Types/turtle_types.h"

uint8_t hexToDecimal(const char* hexString, uint64_t * value);
uint8_t stringToInteger(const char* numString, uint64_t* value);

#endif /* IO */