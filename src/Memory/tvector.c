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

#include "./tvector.h"

int8_t TVector_initVector(TVector * vec, size_t elementSize, uint32_t initialElementCount)
{
    if(vec == NULL)
    {
        return ERR_NULL_ARGUMENT;
    }
    if(elementSize < 1)
    {
        return ERR_INVALID_ARGUMENT;
    }
    if(initialElementCount < 1)
    {
        initialElementCount = 4; // Arbitrary number.
    }

    vec->pData = malloc(elementSize * initialElementCount);
    if(vec->pData == NULL)
    {
        return ERR_MEMORY_ALLOCATION_FAILED;
    }

    vec->currElement = 0;
    vec->numElements = 0;
    vec->elementSize = elementSize;
    vec->totalFreeElements = initialElementCount;
    memset(vec->pData, 0, elementSize * initialElementCount);
    if(vec->pData == NULL)
    {
        return ERR_NO_MEMORY;
    }
    return ERR_NONE;
}

int8_t TVector_addElement(TVector * vec, void * element)
{
    if(vec == NULL || element == NULL)
    {
        return ERR_NULL_ARGUMENT;
    }
    if(vec->numElements != 0 && vec->numElements >= vec->totalFreeElements - 1)
    {
        void * pTmp = NULL;

        // Reallocate enough memory to hold an extra 10 elements.
        pTmp = realloc(vec->pData, (vec->totalFreeElements + 10) * vec->elementSize);
        if(pTmp == NULL)
        {
            return ERR_NO_MEMORY;
        }

        vec->totalFreeElements += 10;
        memset(&pTmp[vec->numElements * vec->elementSize], 0, (vec->totalFreeElements - vec->numElements) * vec->elementSize);
        vec->pData = pTmp;
    }

    memcpy(&vec->pData[vec->numElements * vec->elementSize], element, vec->elementSize);
    vec->numElements++;
    return ERR_NONE;
}

int8_t TVector_getElement(const TVector * vec, void * element, uint32_t index)
{
    if(vec == NULL || element == NULL)
    {
        return ERR_NULL_ARGUMENT;
    }
    if(index >= vec->numElements || vec->elementSize < 1 || vec->numElements < 1 )
    {
        return ERR_INVALID_ARGUMENT;
    }
    memcpy(element, &vec->pData[index * vec->elementSize], vec->elementSize);
    return ERR_NONE;
}

int8_t TVector_getFirst(const TVector * vec, void * element)
{
    if(vec == NULL || element == NULL)
    {
        return ERR_NULL_ARGUMENT;
    }
    if(vec->elementSize < 1 || vec->numElements < 1)
    {
        return ERR_INVALID_ARGUMENT;
    }

    memcpy(element, vec->pData, vec->elementSize);
    return ERR_NONE;
}

int8_t TVector_removeElement(TVector * vec, uint32_t index)
{
    if(vec == NULL)
    {
        return ERR_NULL_ARGUMENT;
    }
    if(index >= vec->numElements || vec->elementSize < 1 || vec->numElements < 1)
    {
        return ERR_INVALID_ARGUMENT;
    }

    for(uint32_t i = index; i < vec->numElements - 1; i++)
    {
        memcpy(&vec->pData[i * vec->elementSize], &vec->pData[(i + 1) * vec->elementSize], vec->elementSize);
        memset(&vec->pData[(i + 1) * vec->elementSize], 0, vec->elementSize);
    }
    return ERR_NONE;
}

int8_t TVector_deinitVector(TVector * vec)
{
    if(vec->elementSize == 0 || vec->numElements == 0 ||
       vec->totalFreeElements == 0 || vec->pData == NULL)
    {
        return ERR_INVALID_ARGUMENT; // Not really a problem.
    }

    // TODO: Do we really need to set these to zero??
    vec->currElement       = 0;
    vec->elementSize       = 0;
    vec->numElements       = 0;
    vec->totalFreeElements = 0;

    free(vec->pData);
    vec->pData = NULL;
    return ERR_NONE;
}

#ifdef UNITTEST

static void test_TVector_initVector_zeroInitialSize()
{
    TVector vec = {0};
    int8_t err = ERR_NONE;

    err = TVector_initVector(&vec, sizeof(int), 0);
    assert(err == ERR_NONE);
    assert(vec.pData != NULL);
    assert(vec.currElement == 0);
    assert(vec.numElements == 0);
    assert(vec.elementSize == sizeof(int));
    assert(vec.totalFreeElements == 4);

    free(vec.pData);
}

static void test_TVector_initVector_initialSizeSet()
{
    TVector vec = {0};
    int8_t err = ERR_NONE;

    err = TVector_initVector(&vec, sizeof(int), 5);
    assert(err == ERR_NONE);
    assert(vec.pData != NULL);
    assert(vec.totalFreeElements == 5);

    free(vec.pData);
}

static void test_TVector_initVector_zeroSizeElement()
{
    TVector vec = {0};
    int8_t err = ERR_NONE;

    err = TVector_initVector(&vec, 0, 0);
    assert(err == ERR_INVALID_ARGUMENT);
    assert(vec.pData == NULL);
}

static void test_TVector_initVector_nullvector()
{
    int8_t err = ERR_NONE;

    err = TVector_initVector(NULL, 1, 0);
    assert(err == ERR_NULL_ARGUMENT);
}

static void test_TVector_addElement_validUsage_triggerResize()
{
    TVector vec = {0};
    int num = 1;
    int res = 0;
    int8_t err = ERR_NONE;

    err = TVector_initVector(&vec, sizeof(int), 1);
    if(err != ERR_NONE)
    {
        return;
    }

    err = TVector_addElement(&vec, &num);
    assert(err == ERR_NONE);
    memcpy(&res, &vec.pData[0], vec.elementSize);
    assert(res == 1);


    ++num;
    err = TVector_addElement(&vec, &num);
    assert(err == ERR_NONE);
    memcpy(&res, &vec.pData[0], vec.elementSize); // Confirm we don't overwrite the previous entry.
    assert(res == 1);
    memcpy(&res, &vec.pData[1 * vec.elementSize], vec.elementSize);
    assert(res == 2);

    ++num;
    err = TVector_addElement(&vec, &num);
    assert(err == ERR_NONE);
    memcpy(&res, &vec.pData[0 * vec.elementSize], vec.elementSize); // Confirm we don't overwrite the previous entry.
    assert(res == 1);
    memcpy(&res, &vec.pData[1 * vec.elementSize], vec.elementSize);
    assert(res == 2);
    memcpy(&res, &vec.pData[2 * vec.elementSize], vec.elementSize);
    assert(res == 3);

    free(vec.pData);
}

static void test_TVector_addElement_validUsage_nullArguments()
{
    TVector vec = {0};
    int num = 1;
    int res = 0;
    int8_t err = ERR_NONE;

    err = TVector_initVector(&vec, sizeof(int), 1);
    if(err != ERR_NONE)
    {
        return;
    }

    err = TVector_addElement(NULL, &num);
    assert(err == ERR_NULL_ARGUMENT);

    err = ERR_NONE;
    err = TVector_addElement(&vec, NULL);
    assert(err == ERR_NULL_ARGUMENT);
}

static void test_TVector_getElement_validUsage()
{
    TVector vec = {0};
    int buff[] = {1, 2, 3};

    vec.elementSize = sizeof(int);
    vec.numElements = 3;
    vec.totalFreeElements = 3;
    vec.pData = &buff;

    int result = 0;
    int8_t err = ERR_NONE;

    err = TVector_getElement(&vec, &result, 0);
    assert(err == ERR_NONE);
    assert(result == 1);

    result = 0;
    err = TVector_getElement(&vec, &result, 1);
    assert(err == ERR_NONE);
    assert(result == 2);

    result = 0;
    err = TVector_getElement(&vec, &result, 1);
    assert(err == ERR_NONE);
    assert(result == 2);
}

static void test_TVector_getElement_nullArguments()
{
    TVector vec = {0};
    int buff[] = {1, 2, 3};

    vec.elementSize = sizeof(int);
    vec.numElements = 3;
    vec.totalFreeElements = 3;
    vec.pData = &buff;

    int result = 0;
    int8_t err = ERR_NONE;

    err = TVector_getElement(NULL, &result, 0);
    assert(err == ERR_NULL_ARGUMENT);

    err = TVector_getElement(&vec, NULL, 0);
    assert(err == ERR_NULL_ARGUMENT);
}

static void test_TVector_getElement_invalidVetorStructure()
{
    TVector vec = {0};
    int buff[] = {1, 2, 3};

    vec.elementSize = 0;
    vec.numElements = 3;
    vec.totalFreeElements = 3;
    vec.pData = &buff;

    int result = 0;
    int8_t err = ERR_NONE;

    err = TVector_getElement(NULL, &result, 0);
    assert(err == ERR_NULL_ARGUMENT);

    vec.elementSize = sizeof(int);
    vec.numElements = 0;
    vec.totalFreeElements = 3;
    vec.pData = &buff;
    err = TVector_getElement(&vec, NULL, 0);
    assert(err == ERR_NULL_ARGUMENT);

    vec.elementSize = sizeof(int);
    vec.numElements = 3;
    vec.totalFreeElements = 3;
    vec.pData = &buff;
    err = TVector_getElement(&vec, &result, 100);
    assert(err == ERR_INVALID_ARGUMENT);
}

static void test_TVector_getFirst_validUsage()
{
    TVector vec = {0};
    int num = 1;
    int res = 0;
    int8_t err = ERR_NONE;

    err = TVector_initVector(&vec, sizeof(int), 1);
    if(err != ERR_NONE)
    {
        return;
    }

    err = TVector_addElement(&vec, &num);
    assert(err == ERR_NONE);
    err = TVector_getFirst(&vec, &res);
    assert(err == ERR_NONE);
    assert(res == 1);
}

static void test_TVector_getFirst_nullArguments()
{
    TVector vec = {0};
    int num = 1;
    int res = 0;
    int8_t err = ERR_NONE;

    err = TVector_initVector(&vec, sizeof(int), 1);
    if(err != ERR_NONE)
    {
        return;
    }

    err = TVector_addElement(&vec, &num);
    assert(err == ERR_NONE);

    err = TVector_getFirst(NULL, &res);
    assert(err == ERR_NULL_ARGUMENT);

    err = TVector_getFirst(&vec, NULL);
    assert(err == ERR_NULL_ARGUMENT);    
}

static void test_TVector_removeElement_validUsage()
{
    TVector vec = {0};
    int buff[] = {1, 2, 3};

    vec.elementSize = sizeof(int);
    vec.numElements = 3;
    vec.totalFreeElements = 3;
    vec.pData = &buff;

    int result = 0;
    int8_t err = ERR_NONE;

    err = TVector_getElement(&vec, &result, 0);
    assert(err == ERR_NONE);
    assert(result == 1);
    result = 0;
    err = TVector_removeElement(&vec, 0);
    assert(err == ERR_NONE);
    err = TVector_getElement(&vec, &result, 0);
    assert(err == ERR_NONE);
    assert(result == 2);
}

static void test_TVector_removeElement_invalidArguments()
{
    TVector vec = {0};
    int buff[] = {1, 2, 3};

    vec.elementSize = sizeof(int);
    vec.numElements = 3;
    vec.totalFreeElements = 3;
    vec.pData = &buff;

    int result = 0;
    int8_t err = ERR_NONE;

    err = TVector_removeElement(NULL, 0);
    assert(err == ERR_NULL_ARGUMENT);


    vec.elementSize = sizeof(int);
    vec.numElements = 3;
    vec.totalFreeElements = 3;
    err = TVector_removeElement(&vec, 10);
    assert(err == ERR_INVALID_ARGUMENT);

    vec.elementSize = 0;
    vec.numElements = 3;
    vec.totalFreeElements = 3;
    err = TVector_removeElement(&vec, 0);
    assert(err == ERR_INVALID_ARGUMENT);

    vec.elementSize = sizeof(int);
    vec.numElements = 0;
    vec.totalFreeElements = 3;
    err = TVector_removeElement(&vec, 10);
    assert(err == ERR_INVALID_ARGUMENT);
}

void TVectorTestSuite()
{
    test_TVector_initVector_zeroInitialSize();
    test_TVector_initVector_initialSizeSet();
    test_TVector_initVector_zeroSizeElement();
    test_TVector_initVector_nullvector();

    test_TVector_addElement_validUsage_triggerResize();
    test_TVector_addElement_validUsage_nullArguments();

    test_TVector_getElement_validUsage();
    test_TVector_getElement_nullArguments();
    test_TVector_getElement_invalidVetorStructure();

    test_TVector_getFirst_validUsage();
    test_TVector_getFirst_nullArguments();

    test_TVector_removeElement_validUsage();
    test_TVector_removeElement_invalidArguments();
}
#endif /* UNITTEST */