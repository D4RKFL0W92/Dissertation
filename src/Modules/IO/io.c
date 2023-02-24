#include "./io.h"

uint64_t hexToDecimal(const char* hexString)
{
    uint64_t value           = 0;
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
        // TODO: Check hexString[digitOffset] is a valid hex digit.
        switch (hexString[digitOffset])
        {
            case '0':
                value += 0 * pow(16, offsetExponent);
                break;
            case '1':
                value += 1 * pow(16, offsetExponent);
                break;
            case '2':
                value += 2 * pow(16, offsetExponent);
                break;
            case '3':
                value += 3 * pow(16, offsetExponent);
                break;
            case '4':
                value += 4 * pow(16, offsetExponent);
                break;
            case '5':
                value += 5 * pow(16, offsetExponent);
                break;
            case '6':
                value += 6 * pow(16, offsetExponent);
                break;
            case '7':
                value += 7 * pow(16, offsetExponent);
                break;
            case '8':
                value += 8 * pow(16, offsetExponent);
                break;
            case '9':
                value += 9 * pow(16, offsetExponent);
                break;
            case 'a':
            case 'A':
                value += 10 * pow(16, offsetExponent);
                break;
            case 'b':
            case 'B':
                value += 11 * pow(16, offsetExponent);
                break;
            case 'c':
            case 'C':
                value += 12 * pow(16, offsetExponent);
                break;
            case 'd':
            case 'D':
                value += 13 * pow(16, offsetExponent);
                break;
            case 'e':
            case 'E':
                value += 14 * pow(16, offsetExponent);
                break;
            case 'f':
            case 'F':
                value += 15 * pow(16, offsetExponent);
                break;
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
    assert(hexToDecimal("0xf00bcf11") == 4027305745);

    /* Do they have to be 4 bytes long (Can only store U64_MAX). */
    assert(hexToDecimal("0xfca")      == 4042);
    assert(hexToDecimal("0xffca")     == 65482);
    assert(hexToDecimal("0xfc43a")    == 1033274);
    assert(hexToDecimal("0xff")       == 255);
    assert(hexToDecimal("0xfcabe5")   == 16559077);
    assert(hexToDecimal("0xaafcade")  == 179292894);
}

void ioTestSuite()
{
    test_hexToDecimal_valid();
}

#endif