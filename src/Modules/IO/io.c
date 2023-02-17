#include "./io.h"

uint64_t hexToDecimal(const char* hexString)
{
    uint64_t value           = 0;
    uint64_t tmpValue        = 0;
    uint8_t  offsetExponent  = 0;
    int16_t  hexStrLen       = 0;

    if(hexString == NULL)
    {
        return 0;
    }

    if(hexString[0] != '0' && (hexString[1] != 'x' || hexString[1] != 'X'))
    {
        return 0;
    }

    hexStrLen = strlen(hexString);

    for(int digitOffset = hexStrLen - 1; digitOffset > 1; --digitOffset, ++offsetExponent)
    {
        if((char) hexString[digitOffset] == '0')
        {
            if(offsetExponent == 0)
            {
                value += 0;
            }
            else
            {
                value += 0;
            }
        }
        else if((char) hexString[digitOffset] == '1')
        {
            if(offsetExponent == 0)
            {
                value += 1;
            }
            else
            {
                tmpValue = pow(16, offsetExponent);
                value    += 10 * tmpValue;
            }
        }
        else if((char) hexString[digitOffset] == '2')
        {
            if(offsetExponent == 0)
            {
                value += 2;
            }
            else
            {
                tmpValue = pow(16, offsetExponent);
                value    += 2 * tmpValue;
            }
        }
        else if((char) hexString[digitOffset] == '3')
        {
            if(offsetExponent == 0)
            {
                value += 3;
            }
            else
            {
                tmpValue = pow(16, offsetExponent);
                value    += 3 * tmpValue;
            }
        }
        else if((char) hexString[digitOffset] == '4')
        {
            if(offsetExponent == 0)
            {
                value += 4;
            }
            else
            {
                tmpValue = pow(16, offsetExponent);
                value    += 4 * tmpValue;
            }
        }
        else if((char) hexString[digitOffset] == '5')
        {
            if(offsetExponent == 0)
            {
                value += 5;
            }
            else
            {
                tmpValue = pow(16, offsetExponent);
                value    += 5 * tmpValue;
            }
        }
        else if((char) hexString[digitOffset] == '6')
        {
            if(offsetExponent == 0)
            {
                value += 6;
            }
            else
            {
                tmpValue = pow(16, offsetExponent);
                value    += 6 * tmpValue;
            }
        }
        else if((char) hexString[digitOffset] == '7')
        {
            if(offsetExponent == 0)
            {
                value += 7;
            }
            else
            {
                tmpValue = pow(16, offsetExponent);
                value    += 7 * tmpValue;
            }
        }
        else if((char) hexString[digitOffset] == '8')
        {
            if(offsetExponent == 0)
            {
                value += 8;
            }
            else
            {
                tmpValue = pow(16, offsetExponent);
                value    += 8 * tmpValue;
            }
        }
        else if((char) hexString[digitOffset] == '9')
        {
            if(offsetExponent == 0)
            {
                value += 9;
            }
            else
            {
                tmpValue = pow(16, offsetExponent);
                value    += 9 * tmpValue;
            }
        }
        else if((char) hexString[digitOffset] == 'a' || (char) hexString[digitOffset] == 'A')
        {
            if(offsetExponent == 0)
            {
                value += 10;
            }
            else
            {
                tmpValue = pow(16, offsetExponent);
                value    += 10 * tmpValue;
            }
        }
        else if((char) hexString[digitOffset] == 'b' || (char) hexString[digitOffset] == 'B')
        {
            if(offsetExponent == 0)
            {
                value += 11;
            }
            else
            {
                tmpValue = pow(16, offsetExponent);
                value    += 11 * tmpValue;
            }
        }
        else if((char) hexString[digitOffset] == 'c' || (char) hexString[digitOffset] == 'C')
        {
            if(offsetExponent == 0)
            {
                value += 12;
            }
            else
            {
                tmpValue = pow(16, offsetExponent);
                value    += 12 * tmpValue;
            }
        }
        else if((char) hexString[digitOffset] == 'd' || (char) hexString[digitOffset] == 'D')
        {
            if(offsetExponent == 0)
            {
                value += 13;
            }
            else
            {
                tmpValue = pow(16, offsetExponent);
                value    += 13 * tmpValue;
            }
        }
        else if((char) hexString[digitOffset] == 'e' || (char) hexString[digitOffset] == 'E')
        {
            if(offsetExponent == 0)
            {
                value += 14;
            }
            else
            {
                tmpValue = pow(16, offsetExponent);
                value    += 14 * tmpValue;
            }
        }
        else if((char) hexString[digitOffset] == 'f' || (char) hexString[digitOffset] == 'F')
        {
            if(offsetExponent == 0)
            {
                value += 15;
            }
            else
            {
                tmpValue = pow(16, offsetExponent);
                value    += 15 * tmpValue;
            }
        }
    }
    return value;
}



#ifdef UNITTEST

void test_hexToDecimal_valid()
{
    assert(hexToDecimal("0x00000001") == 1);
    assert(hexToDecimal("0x00000002") == 2);
    assert(hexToDecimal("0x00000003") == 3);
    assert(hexToDecimal("0x00000004") == 4);
    assert(hexToDecimal("0x00000005") == 5);
    assert(hexToDecimal("0x00000006") == 6);
    assert(hexToDecimal("0x00000007") == 7);
    assert(hexToDecimal("0x00000008") == 8);
    assert(hexToDecimal("0x00000009") == 9);
    assert(hexToDecimal("0x0000000a") == 10);
    assert(hexToDecimal("0x0000000b") == 11);
    assert(hexToDecimal("0x0000000c") == 12);
    assert(hexToDecimal("0x0000000d") == 13);
    assert(hexToDecimal("0x0000000e") == 14);
    assert(hexToDecimal("0x0000000f") == 15);

    /* Try some random ones */
    assert(hexToDecimal("0xffffffff") == 4294967295);
    assert(hexToDecimal("0xde5469ab") == 3730074027);
    assert(hexToDecimal("0x42424242") == 1111638594);
    uint64_t val = hexToDecimal("0xf00bcf11");
    assert(hexToDecimal("0xf00bcf11") == 4027305745);

    /* Do they have to be 4 bytes long (Can only store U64_MAX). */
    assert(hexToDecimal("0xfca") == 4042);
}

void ioTestSuite()
{
    test_hexToDecimal_valid();
}

#endif