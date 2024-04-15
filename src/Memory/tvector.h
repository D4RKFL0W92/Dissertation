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

#ifndef _TLIST_
#define _TLIST_

#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "../Types/turtle_types.h"

typedef struct VECTOR
{
    uint32_t numElements;        /* Number of currently initialised elements. */
    size_t   elementSize;        /* Size in bytes of a single entry. */
    uint32_t totalFreeElements;  /* Total size of allocated memory (measured in how many elements it can store). */
    void *   pData;              /* Pointer to vector data, if this stores dynamically allocated memory
                                    pointer then they must be free'd seperately. */
} TVector;

int8_t TVector_initVector(TVector * vec, size_t elementSize, uint32_t initialElementCount);
int8_t TVector_addElement(TVector * vec, void * element);
int8_t TVector_getElement(const TVector * vec, void * element, uint32_t index);
int8_t TVector_getFirst(const TVector * vec, void * element);
int8_t TVector_removeElement(TVector * vec, uint32_t index);

int8_t TVector_deinitVector(TVector * vec);

#ifdef UNITTEST
void TVectorTestSuite();
#endif /* UNITTEST */

#endif /* _TLIST_ */