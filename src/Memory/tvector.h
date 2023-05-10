#ifndef _TLIST_
#define _TLIST_

#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "../Types/turtle_types.h"

typedef struct VECTOR
{
    uint32_t currElement;        /* Index to current selected element. */
    uint32_t numElements;        /* Number of currently initialised elements. */
    size_t   elementSize;        /* Size in bytes of a single entry. */
    uint32_t totalFreeElements;  /* Total size of allocated memory (measured in how many elements it can store). */
    void *   pData;
} TVector;

int8_t TVector_initVector(TVector * vec, size_t elementSize, uint32_t initialElementCount);
int8_t TVector_addElement(TVector * vec, void * element);
int8_t TVector_getElement(TVector * vec, void * element, uint32_t index);
int8_t TVector_getFirst(TVector * vec, void * element);

// int8_t TVector_getNext(TVector * vec, void * element);


int8_t TVector_deinitVector(TVector * vec);

#ifdef UNITTEST
void TVectorTestSuite();
#endif /* UNITTEST */

#endif /* _TLIST_ */