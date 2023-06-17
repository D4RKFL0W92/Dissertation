#include "./io.h"

/* TODO: Write unit tests for this function. */
BOOL isHexadecimalCharacter(char digit)
{
  if(isdigit(digit))
  {
    return TRUE;
  }
  else if(digit >= 0x41 && digit <= 0x46)
  {
    return TRUE;
  }
  else if(digit >= 0x61 && digit <= 0x66)
  {
    return TRUE;
  }
  return FALSE;
}

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

  if(numString == NULL || value == NULL)
  {
    return ERR_NULL_ARGUMENT;
  }

  if(numString[0] == '0' && numString[1] == 'x' || numString[1] == 'X')
  {
    err = hexToDecimal(numString, &lValue);
    if(err != ERR_NONE)
    {
      return err; // Propergate the error from hexToDecimal
    }
  }
  // TODO: Add logic to handle binary numbers
  else
  {
    int len = strlen(numString);
    uint8_t i = 0;

    if(numString[0] == '-' || numString[0] == '+') // Account for negative/positive sign.
    {
      i++;
    }
    for(i; i < len-1; i++)
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

void unittest_isHexadecimalCharacter_legalChars()
{
  assert( isHexadecimalCharacter('0') == TRUE );
  assert( isHexadecimalCharacter('1') == TRUE );
  assert( isHexadecimalCharacter('2') == TRUE );
  assert( isHexadecimalCharacter('3') == TRUE );
  assert( isHexadecimalCharacter('4') == TRUE );
  assert( isHexadecimalCharacter('5') == TRUE );
  assert( isHexadecimalCharacter('6') == TRUE );
  assert( isHexadecimalCharacter('7') == TRUE );
  assert( isHexadecimalCharacter('8') == TRUE );
  assert( isHexadecimalCharacter('9') == TRUE );
  assert( isHexadecimalCharacter('a') == TRUE );
  assert( isHexadecimalCharacter('b') == TRUE );
  assert( isHexadecimalCharacter('c') == TRUE );
  assert( isHexadecimalCharacter('d') == TRUE );
  assert( isHexadecimalCharacter('e') == TRUE );
  assert( isHexadecimalCharacter('f') == TRUE );
  assert( isHexadecimalCharacter('A') == TRUE );
  assert( isHexadecimalCharacter('B') == TRUE );
  assert( isHexadecimalCharacter('C') == TRUE );
  assert( isHexadecimalCharacter('D') == TRUE );
  assert( isHexadecimalCharacter('E') == TRUE );
  assert( isHexadecimalCharacter('F') == TRUE );
}

void unittest_isHexadecimalCharacter_illegalChars()
{
  assert( isHexadecimalCharacter('z') == FALSE );
  assert( isHexadecimalCharacter('y') == FALSE );
  assert( isHexadecimalCharacter('x') == FALSE );
  assert( isHexadecimalCharacter('&') == FALSE );
  assert( isHexadecimalCharacter('^') == FALSE );
  assert( isHexadecimalCharacter('@') == FALSE );
  assert( isHexadecimalCharacter(';') == FALSE );
  assert( isHexadecimalCharacter('k') == FALSE );
  assert( isHexadecimalCharacter('Q') == FALSE );
  assert( isHexadecimalCharacter('I') == FALSE );
  assert( isHexadecimalCharacter('P') == FALSE );
  assert( isHexadecimalCharacter('W') == FALSE );
  assert( isHexadecimalCharacter('X') == FALSE );
  assert( isHexadecimalCharacter('`') == FALSE );
  assert( isHexadecimalCharacter('~') == FALSE );
  assert( isHexadecimalCharacter(']') == FALSE );
  assert( isHexadecimalCharacter('H') == FALSE );
  assert( isHexadecimalCharacter('{') == FALSE );
  assert( isHexadecimalCharacter('\t') == FALSE );
  assert( isHexadecimalCharacter('\n') == FALSE );
  assert( isHexadecimalCharacter('\\') == FALSE );
  assert( isHexadecimalCharacter('\"') == FALSE );
}

void unittest_stringToInteger_legalUsage()
{
  uint64_t value = 0;
  uint8_t err = ERR_NONE;

  err = stringToInteger("1", &value);
  assert(err == ERR_NONE);
  assert(value == 1);

  err = stringToInteger("0", &value);
  assert(err == ERR_NONE);
  assert(value == 0);

  err = stringToInteger("0X555555", &value);
  assert(err == ERR_NONE);
  assert(value == 0X555555);

  err = stringToInteger("1347", &value);
  assert(err == ERR_NONE);
  assert(value == 1347);

  err = stringToInteger("0x9965", &value);
  assert(err == ERR_NONE);
  assert(value == 0x9965);

  err = stringToInteger("-1", &value);
  assert(err == ERR_NONE);
  assert((int)value == -1);

  err = stringToInteger("-54321", &value);
  assert(err == ERR_NONE);
  assert((int)value == -54321);

  err = stringToInteger("-20", &value);
  assert(err == ERR_NONE);
  assert((int)value == -20);
}

void unittest_stringToInteger_illegalUsage()
{
  uint64_t value = 0;
  uint8_t err = ERR_NONE;

  err = stringToInteger("aa", &value);
  assert(err == ERR_FORMAT_NOT_SUPPORTED);

  err = stringToInteger("aa", NULL);
  assert(err == ERR_NULL_ARGUMENT);

  err = stringToInteger(NULL, &value);
  assert(err == ERR_NULL_ARGUMENT);
}

void unittest_hexToDecimal_valid()
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
  unittest_isHexadecimalCharacter_legalChars();
  unittest_isHexadecimalCharacter_illegalChars();

  unittest_stringToInteger_legalUsage();
  unittest_stringToInteger_illegalUsage();

  unittest_hexToDecimal_valid();
}

#endif