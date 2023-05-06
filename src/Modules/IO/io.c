#include "./io.h"

uint8_t hexToDecimal(const char* hexString, uint64_t * value)
{
  uint8_t  offsetExponent  = 0;
  int16_t  hexStrLen     = 0;

  uint64_t lValue       = 0;

  if(hexString == NULL)
  {
    return ERR_NULL_ARGUMENT;
  }

  if(hexString[0] != '0' && (hexString[1] != 'x' || hexString[1] != 'X'))
  {
    return ERR_FORMAT_NOT_SUPPORTED;
  }

  hexStrLen = strlen(hexString);

  for(int digitOffset = hexStrLen - 1; digitOffset > 1; --digitOffset, ++offsetExponent)
  {
    // TODO: Check hexString[digitOffset] is a valid hex digit.
    switch (hexString[digitOffset])
    {
      case '0':
        lValue += 0 * pow(16, offsetExponent);
        break;
      case '1':
        lValue += 1 * pow(16, offsetExponent);
        break;
      case '2':
        lValue += 2 * pow(16, offsetExponent);
        break;
      case '3':
        lValue += 3 * pow(16, offsetExponent);
        break;
      case '4':
        lValue += 4 * pow(16, offsetExponent);
        break;
      case '5':
        lValue += 5 * pow(16, offsetExponent);
        break;
      case '6':
        lValue += 6 * pow(16, offsetExponent);
        break;
      case '7':
        lValue += 7 * pow(16, offsetExponent);
        break;
      case '8':
        lValue += 8 * pow(16, offsetExponent);
        break;
      case '9':
        lValue += 9 * pow(16, offsetExponent);
        break;
      case 'a':
      case 'A':
        lValue += 10 * pow(16, offsetExponent);
        break;
      case 'b':
      case 'B':
        lValue += 11 * pow(16, offsetExponent);
        break;
      case 'c':
      case 'C':
        lValue += 12 * pow(16, offsetExponent);
        break;
      case 'd':
      case 'D':
        lValue += 13 * pow(16, offsetExponent);
        break;
      case 'e':
      case 'E':
        lValue += 14 * pow(16, offsetExponent);
        break;
      case 'f':
      case 'F':
        lValue += 15 * pow(16, offsetExponent);
        break;
    }
  }
  *value = lValue;
  return ERR_NONE;
}

uint8_t stringToInteger(const char* numString, uint64_t* value)
{
  uint8_t err = 0;
  uint64_t lValue = 0;

  if(numString[0] == '0' && numString[1] == 'x' || numString[1] == 'X')
      {
        err = hexToDecimal(numString, &lValue);
        if(err == ERR_UNKNOWN)
        {
          printf("Zero Offset Was Given.");
          exit(-1);
        }
      }
      else
      {
        int len = strlen(numString);
        for(uint8_t i = 0; i < len-1; i++)
        {
          if(!isdigit(numString[i]))
          {
            return ERR_FORMAT_NOT_SUPPORTED;
          }
        }
        lValue = atol(numString);
      }
      *value = lValue;
      return ERR_NONE;
}

#ifdef UNITTEST

void test_hexToDecimal_valid()
{
  uint8_t err = 0;
  uint64_t value = 0;

  err = hexToDecimal("0x00000001", &value);
  assert(err == ERR_NONE);
  assert(value == 1);
  err = 0;
  value = 0;

  err = hexToDecimal("0x00000002", &value);
  assert(err == ERR_NONE);
  assert(value == 2);
  err = 0;
  value = 0;

  err = hexToDecimal("0x00000003", &value);
  assert(err == ERR_NONE);
  assert(value == 3);
  err = 0;
  value = 0;

  err = hexToDecimal("0x00000004", &value);
  assert(err == ERR_NONE);
  assert(value == 4);
  err = 0;
  value = 0;

  err = hexToDecimal("0x00000005", &value);
  assert(err == ERR_NONE);
  assert(value == 5);
  err = 0;
  value = 0;

  err = hexToDecimal("0x00000006", &value);
  assert(err == ERR_NONE);
  assert(value == 6);
  err = 0;
  value = 0;

  err = hexToDecimal("0x00000007", &value);
  assert(err == ERR_NONE);
  assert(value == 7);
  err = 0;
  value = 0;

  err = hexToDecimal("0x00000008", &value);
  assert(err == ERR_NONE);
  assert(value == 8);
  err = 0;
  value = 0;

  err = hexToDecimal("0x00000009", &value);
  assert(err == ERR_NONE);
  assert(value == 9);
  err = 0;
  value = 0;

  err = hexToDecimal("0x0000000a", &value);
  assert(err == ERR_NONE);
  assert(value == 10);
  err = 0;
  value = 0;

  err = hexToDecimal("0x0000000b", &value);
  assert(err == ERR_NONE);
  assert(value == 11);
  err = 0;
  value = 0;

  err = hexToDecimal("0x0000000c", &value);
  assert(err == ERR_NONE);
  assert(value == 12);
  err = 0;
  value = 0;

  err = hexToDecimal("0x0000000d", &value);
  assert(err == ERR_NONE);
  assert(value == 13);
  err = 0;
  value = 0;

  err = hexToDecimal("0x0000000e", &value);
  assert(err == ERR_NONE);
  assert(value == 14);
  err = 0;
  value = 0;

  err = hexToDecimal("0x0000000f", &value);
  assert(err == ERR_NONE);
  assert(value == 15);
  err = 0;
  value = 0;

  /* Try some random ones */
  err = hexToDecimal("0xffffffff", &value);
  assert(err == ERR_NONE);
  assert(value == 4294967295);
  err = 0;
  value = 0;

  err = hexToDecimal("0xde5469ab", &value);
  assert(err == ERR_NONE);
  assert(value == 3730074027);
  err = 0;
  value = 0;

  err = hexToDecimal("0x42424242", &value);
  assert(err == ERR_NONE);
  assert(value == 1111638594);
  err = 0;
  value = 0;

  err = hexToDecimal("0xf00bcf11", &value);
  assert(err == ERR_NONE);
  assert(value == 4027305745);
  err = 0;
  value = 0;

  /* Do they have to be 4 bytes long (Can only store U64_MAX). */
  err = hexToDecimal("0xfca", &value);
  assert(err == ERR_NONE);
  assert(value == 4042);
  err = 0;
  value = 0;

  err = hexToDecimal("0xffca", &value);
  assert(err == ERR_NONE);
  assert(value == 65482);
  err = 0;
  value = 0;

  err = hexToDecimal("0xfc43a", &value);
  assert(err == ERR_NONE);
  assert(value == 1033274);
  err = 0;
  value = 0;

  err = hexToDecimal("0xff", &value);
  assert(err == ERR_NONE);
  assert(value == 255);
  err = 0;
  value = 0;

  err = hexToDecimal("0xfcabe5", &value);
  assert(err == ERR_NONE);
  assert(value == 16559077);
  err = 0;
  value = 0;

  err = hexToDecimal("0xaafcade", &value);
  assert(err == ERR_NONE);
  assert(value == 179292894);
  err = 0;
  value = 0;

}

void ioTestSuite()
{
  test_hexToDecimal_valid();
}

#endif