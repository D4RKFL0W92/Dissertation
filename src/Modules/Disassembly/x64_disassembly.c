#include "./x64_disassembly.h"

/* Extract data contained in the ModR/M byte. */
static int8_t getModRmData16Bit(uint8_t modRmByte, uint8_t* effectiveAddr, uint8_t* reg)
{
  if(effectiveAddr == NULL || reg == NULL)
  {
    return ERR_NULL_ARGUMENT;
  }

  /* Get the effective address. */
  if( !(modRmByte >> 7 & 1) && !(modRmByte >> 6 & 1))   // Mod: 0b00
  {
    if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b000
    {
      *effectiveAddr = __BX_ADD_SI__; // [BX+SI]
    }
    else if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b001
    {
      *effectiveAddr = __BX_ADD_DI__; // [BX+DI]
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b010
    {
      *effectiveAddr = __BP_ADD_SI__; // [BP+SI]
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b011
    {
      *effectiveAddr = __BP_ADD_DI__; // [BP+DI]
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b100
    {
      *effectiveAddr = __SI__; // SI
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b101
    {
      *effectiveAddr = __DI__; // [DI]
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b110
    {
      *effectiveAddr = DISP_16_SQ; // disp16^2
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b111
    {
      *effectiveAddr = __BX__; // [BX]
    }
  }

  else if( !(modRmByte >> 7 & 1) && (modRmByte >> 6 & 1)) // Mod: 0b01
  {
    if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b000
    {
      *effectiveAddr = __BX_ADD_SI__ADD_DISP8_CUBED; // [BX+SI]+disp8^3
    }
    else if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b001
    {
      *effectiveAddr = __BX_ADD_DI__ADD_DISP8; // [BX+DI]+disp8
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b010
    {
      *effectiveAddr = __BP_ADD_SI__ADD_DISP8; // [BP+SI]+disp8
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b011
    {
      *effectiveAddr = __BP_ADD_DI__ADD_DISP8; // [BP+DI]+disp8
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b100
    {
      *effectiveAddr = __SI__ADD_DISP8; // [SI]+disp8
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b101
    {
      *effectiveAddr = __DI__ADD_DISP8; // [DI]+disp8
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b110
    {
      *effectiveAddr = __BP__ADD_DISP8; // [BP]+disp8
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b111
    {
      *effectiveAddr = __BX__ADD_DISP8; // [BX]+disp8
    }
  }

  else if( (modRmByte >> 7 & 1) && !(modRmByte >> 6 & 1)) // Mod: 0b10
  {
    if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b000
    {
      *effectiveAddr = __BX_ADD_SI__ADD_DISP16; // [BX+SI]+disp16
    }
    else if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b001
    {
      *effectiveAddr = __BX_ADD_DI__ADD_DISP16; // [BX+DI]+disp16
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b010
    {
      *effectiveAddr = __BP_ADD_SI__ADD_DISP16; // [BP+SI]+disp16
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b011
    {
      *effectiveAddr = __BP_ADD_DI__ADD_DISP16; // [BP+DI]+disp16
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b100
    {
      *effectiveAddr = __SI__ADD_DISP16; // [SI]+disp16
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b101
    {
      *effectiveAddr = __DI__ADD_DISP16; // [DI]+disp16
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b110
    {
      *effectiveAddr = __BP__ADD_DISP16; // [BP]+disp16
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b111
    {
      *effectiveAddr = __BX__ADD_DISP16; // [BX]+disp16
    }
  }

  else if( (modRmByte >> 7 & 1) && (modRmByte >> 6 & 1))  // Mod: 0b11
  {
    if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b000
    {
      *effectiveAddr = REG_ZERO_ADDR; // EAX/AX/AL/MM0/XMM0
    }
    else if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b001
    {
      *effectiveAddr = REG_ONE_ADDR; // ECX/CX/CL/MM1/XMM1
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b010
    {
      *effectiveAddr = REG_TWO_ADDR; // EDX/DX/DL/MM2/XMM2
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b011
    {
      *effectiveAddr = REG_THREE_ADDR; //EBX/BX/BL/MM3/XMM3
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b100
    {
      *effectiveAddr = REG_FOUR_ADDR; // ESP/SP/AH/MM4/XMM4
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b101
    {
      *effectiveAddr = REG_FIVE_ADDR; // EBP/BP/CH/MM5/XMM5
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b110
    {
      *effectiveAddr = REG_SIX_ADDR; // ESI/SI/DH/MM6/XMM6
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b111
    {
      *effectiveAddr = REG_SEVEN_ADDR; // EDI/DI/BH/MM7/XMM7
    }
  }

  /* Extract the register value from the modRM byte. */
  // 0b000
  if( !(modRmByte >> 5 & 1) && !(modRmByte >> 4 & 1) && !(modRmByte >> 3 & 1))
  {
    *reg = REG_ZERO;
  }
  // 0b001
  else if( !(modRmByte >> 5 & 1) && !(modRmByte >> 4 & 1) && (modRmByte >> 3 & 1))
  {
    *reg = REG_ONE;
  }
  // 0b010
  else if( !(modRmByte >> 5 & 1) && (modRmByte >> 4 & 1) && !(modRmByte >> 3 & 1))
  {
    *reg = REG_TWO;
  }
  // 0b011
  else if( !(modRmByte >> 5 & 1) && (modRmByte >> 4 & 1) && (modRmByte >> 3 & 1))
  {
    *reg = REG_THREE;
  }
  // 0b100
  else if((modRmByte >> 5 & 1) && !(modRmByte >> 4 & 1) && !(modRmByte >> 3 & 1))
  {
    *reg = REG_FOUR;
  }
  // 0b101
  else if((modRmByte >> 5 & 1) && !(modRmByte >> 4 & 1) && (modRmByte >> 3 & 1))
  {
    *reg = REG_FIVE;
  }
  // 0b110
  else if((modRmByte >> 5 & 1) && (modRmByte >> 4 & 1) && !(modRmByte >> 3 & 1))
  {
    *reg = REG_SIX;
  }
  // 0b111
  else if((modRmByte >> 5 & 1) && (modRmByte >> 4 & 1) && (modRmByte >> 3 & 1))
  {
    *reg = REG_SEVEN;
  }

  return ERR_NONE;
}


#ifdef UNITTEST

static void test_getModRmData16Bit_legalValues()
{
  uint8_t effectiveAddr = 0;
  uint8_t reg = 1; // Set this to a value other than zero for first call.
  int8_t err = ERR_NONE;

  err = getModRmData16Bit(0x00, &effectiveAddr, &reg);
  assert(err == ERR_NONE);
  assert(effectiveAddr == __BX_ADD_SI__);
  assert(reg == REG_ZERO);

  err = getModRmData16Bit(0x48, &effectiveAddr, &reg);
  assert(err == ERR_NONE);
  assert(effectiveAddr == __BX_ADD_SI__ADD_DISP8_CUBED);
  assert(reg == REG_ONE);

  err = getModRmData16Bit(0x92, &effectiveAddr, &reg);
  assert(err == ERR_NONE);
  assert(effectiveAddr == __BP_ADD_SI__ADD_DISP16);
  assert(reg == REG_TWO);

  err = getModRmData16Bit(0xDA, &effectiveAddr, &reg);
  assert(err == ERR_NONE);
  assert(effectiveAddr == REG_TWO_ADDR);
  assert(reg == REG_THREE);

  err = getModRmData16Bit(0xA5, &effectiveAddr, &reg);
  assert(err == ERR_NONE);
  assert(effectiveAddr == __DI__ADD_DISP16);
  assert(reg == REG_FOUR);

  err = getModRmData16Bit(0x6F, &effectiveAddr, &reg);
  assert(err == ERR_NONE);
  assert(effectiveAddr == __BX__ADD_DISP8);
  assert(reg == REG_FIVE);

  err = getModRmData16Bit(0x35, &effectiveAddr, &reg);
  assert(err == ERR_NONE);
  assert(effectiveAddr == __DI__);
  assert(reg == REG_SIX);

  err = getModRmData16Bit(0x3B, &effectiveAddr, &reg);
  assert(err == ERR_NONE);
  assert(effectiveAddr == __BP_ADD_DI__);
  assert(reg == REG_SEVEN);
}

static void test_getModRmData16Bit_nullArguments()
{
  int8_t err = ERR_NONE;
  uint8_t tmp = 0;

  err = getModRmData16Bit(0x00, NULL, &tmp);
  assert(err == ERR_NULL_ARGUMENT);

  err = getModRmData16Bit(0x00, &tmp, NULL);
  assert(err == ERR_NULL_ARGUMENT);
}

// TEST SUITE
void x64_DisassemblyTestSuite()
{
  test_getModRmData16Bit_legalValues();
  test_getModRmData16Bit_nullArguments();
}

#endif /* UNITTEST */