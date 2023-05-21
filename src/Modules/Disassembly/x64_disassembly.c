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
      *effectiveAddr = ADDR_16___BX_ADD_SI__; // [BX+SI]
    }
    else if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b001
    {
      *effectiveAddr = ADDR_16___BX_ADD_DI__; // [BX+DI]
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b010
    {
      *effectiveAddr = ADDR_16___BP_ADD_SI__; // [BP+SI]
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b011
    {
      *effectiveAddr = ADDR_16___BP_ADD_DI__; // [BP+DI]
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b100
    {
      *effectiveAddr = ADDR_16___SI__; // SI
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b101
    {
      *effectiveAddr = ADDR_16___DI__; // [DI]
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b110
    {
      *effectiveAddr = ADDR_16_DISP_16_SQ; // disp16^2
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b111
    {
      *effectiveAddr = ADDR_16___BX__; // [BX]
    }
  }

  else if( !(modRmByte >> 7 & 1) && (modRmByte >> 6 & 1)) // Mod: 0b01
  {
    if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b000
    {
      *effectiveAddr = ADDR_16___BX_ADD_SI__ADD_DISP8_CUBED; // [BX+SI]+disp8^3
    }
    else if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b001
    {
      *effectiveAddr = ADDR_16___BX_ADD_DI__ADD_DISP8; // [BX+DI]+disp8
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b010
    {
      *effectiveAddr = ADDR_16___BP_ADD_SI__ADD_DISP8; // [BP+SI]+disp8
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b011
    {
      *effectiveAddr = ADDR_16___BP_ADD_DI__ADD_DISP8; // [BP+DI]+disp8
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b100
    {
      *effectiveAddr = ADDR_16___SI__ADD_DISP8; // [SI]+disp8
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b101
    {
      *effectiveAddr = ADDR_16___DI__ADD_DISP8; // [DI]+disp8
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b110
    {
      *effectiveAddr = ADDR_16___BP__ADD_DISP8; // [BP]+disp8
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b111
    {
      *effectiveAddr = ADDR_16___BX__ADD_DISP8; // [BX]+disp8
    }
  }

  else if( (modRmByte >> 7 & 1) && !(modRmByte >> 6 & 1)) // Mod: 0b10
  {
    if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b000
    {
      *effectiveAddr = ADDR_16___BX_ADD_SI__ADD_DISP16; // [BX+SI]+disp16
    }
    else if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b001
    {
      *effectiveAddr = ADDR_16___BX_ADD_DI__ADD_DISP16; // [BX+DI]+disp16
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b010
    {
      *effectiveAddr = ADDR_16___BP_ADD_SI__ADD_DISP16; // [BP+SI]+disp16
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b011
    {
      *effectiveAddr = ADDR_16___BP_ADD_DI__ADD_DISP16; // [BP+DI]+disp16
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b100
    {
      *effectiveAddr = ADDR_16___SI__ADD_DISP16; // [SI]+disp16
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b101
    {
      *effectiveAddr = ADDR_16___DI__ADD_DISP16; // [DI]+disp16
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b110
    {
      *effectiveAddr = ADDR_16___BP__ADD_DISP16; // [BP]+disp16
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b111
    {
      *effectiveAddr = ADDR_16___BX__ADD_DISP16; // [BX]+disp16
    }
  }

  else if( (modRmByte >> 7 & 1) && (modRmByte >> 6 & 1))  // Mod: 0b11
  {
    if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b000
    {
      *effectiveAddr = ADDR_16_GPR_REG_ZERO_ADDR; // EAX/AX/AL/MM0/XMM0
    }
    else if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b001
    {
      *effectiveAddr = ADDR_16_GPR_REG_ONE_ADDR; // ECX/CX/CL/MM1/XMM1
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b010
    {
      *effectiveAddr = ADDR_16_GPR_REG_TWO_ADDR; // EDX/DX/DL/MM2/XMM2
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b011
    {
      *effectiveAddr = ADDR_16_GPR_REG_THREE_ADDR; //EBX/BX/BL/MM3/XMM3
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b100
    {
      *effectiveAddr = ADDR_16_GPR_REG_FOUR_ADDR; // ESP/SP/AH/MM4/XMM4
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b101
    {
      *effectiveAddr = ADDR_16_GPR_REG_FIVE_ADDR; // EBP/BP/CH/MM5/XMM5
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b110
    {
      *effectiveAddr = ADDR_16_GPR_REG_SIX_ADDR; // ESI/SI/DH/MM6/XMM6
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b111
    {
      *effectiveAddr = ADDR_16_GPR_REG_SEVEN_ADDR; // EDI/DI/BH/MM7/XMM7
    }
  }

  /* Extract the register value from the modRM byte. */
  // 0b000
  if( !(modRmByte >> 5 & 1) && !(modRmByte >> 4 & 1) && !(modRmByte >> 3 & 1))
  {
    *reg = GPR_REG_ZERO;
  }
  // 0b001
  else if( !(modRmByte >> 5 & 1) && !(modRmByte >> 4 & 1) && (modRmByte >> 3 & 1))
  {
    *reg = GPR_REG_ONE;
  }
  // 0b010
  else if( !(modRmByte >> 5 & 1) && (modRmByte >> 4 & 1) && !(modRmByte >> 3 & 1))
  {
    *reg = GPR_REG_TWO;
  }
  // 0b011
  else if( !(modRmByte >> 5 & 1) && (modRmByte >> 4 & 1) && (modRmByte >> 3 & 1))
  {
    *reg = GPR_REG_THREE;
  }
  // 0b100
  else if((modRmByte >> 5 & 1) && !(modRmByte >> 4 & 1) && !(modRmByte >> 3 & 1))
  {
    *reg = GPR_REG_FOUR;
  }
  // 0b101
  else if((modRmByte >> 5 & 1) && !(modRmByte >> 4 & 1) && (modRmByte >> 3 & 1))
  {
    *reg = GPR_REG_FIVE;
  }
  // 0b110
  else if((modRmByte >> 5 & 1) && (modRmByte >> 4 & 1) && !(modRmByte >> 3 & 1))
  {
    *reg = GPR_REG_SIX;
  }
  // 0b111
  else if((modRmByte >> 5 & 1) && (modRmByte >> 4 & 1) && (modRmByte >> 3 & 1))
  {
    *reg = GPR_REG_SEVEN;
  }

  return ERR_NONE;
}


/* Extract data contained in the ModR/M byte. */
static int8_t getModRmData32Bit(uint8_t modRmByte, uint8_t* effectiveAddr, uint8_t* reg)
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
      *effectiveAddr = ADDR_32__EAX__;
    }
    else if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b001
    {
      *effectiveAddr = ADDR_32__ECX__;
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b010
    {
      *effectiveAddr = ADDR_32__EDX__;
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b011
    {
      *effectiveAddr = ADDR_32__EBX__;
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b100
    {
      *effectiveAddr = ADDR_32_SIB;
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b101
    {
      *effectiveAddr = ADDR_32_DISP32_SQUARED;
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b110
    {
      *effectiveAddr = ADDR_32__ESI__;
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b111
    {
      *effectiveAddr = ADDR_32__EDI__;
    }
  }

  else if( !(modRmByte >> 7 & 1) && (modRmByte >> 6 & 1)) // Mod: 0b01
  {
    if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b000
    {
      *effectiveAddr = ADDR_32__EAX__ADD_DISP8_CUBED;
    }
    else if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b001
    {
      *effectiveAddr = ADDR_32__ECX__ADD_DISP8;
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b010
    {
      *effectiveAddr = ADDR_32__EDX__ADD_DISP8;
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b011
    {
      *effectiveAddr = ADDR_32__EBX__ADD_DISP8;
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b100
    {
      *effectiveAddr = ADDR_32_SIB_ADD_DISP8;
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b101
    {
      *effectiveAddr = ADDR_32__EBP__ADD_DISP8;
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b110
    {
      *effectiveAddr = ADDR_32__ESI__ADD_DISP8;
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b111
    {
      *effectiveAddr = ADDR_32__EDI__ADD_DISP8;
    }
  }

  else if( (modRmByte >> 7 & 1) && !(modRmByte >> 6 & 1)) // Mod: 0b10
  {
    if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b000
    {
      *effectiveAddr = ADDR_32__EAX__ADD_DISP32;
    }
    else if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b001
    {
      *effectiveAddr = ADDR_32__ECX__ADD_DISP32;
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b010
    {
      *effectiveAddr = ADDR_32__EDX__ADD_DISP32;
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b011
    {
      *effectiveAddr = ADDR_32__EBX__ADD_DISP32;
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b100
    {
      *effectiveAddr = ADDR_32_SIB_ADD_DISP32;
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b101
    {
      *effectiveAddr = ADDR_32__EBP__ADD_DISP32;
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b110
    {
      *effectiveAddr = ADDR_32__ESI__ADD_DISP32;
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b111
    {
      *effectiveAddr = ADDR_32__EDI__ADD_DISP32;
    }
  }

  else if( (modRmByte >> 7 & 1) && (modRmByte >> 6 & 1))  // Mod: 0b11
  {
    if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b000
    {
      *effectiveAddr = ADDR_32_GPR_REG_ZERO_ADDR;
    }
    else if( !(modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b001
    {
      *effectiveAddr = ADDR_32_GPR_REG_ONE_ADDR;
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b010
    {
      *effectiveAddr = ADDR_32_GPR_REG_TWO_ADDR;
    }
    else if( !(modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b011
    {
      *effectiveAddr = ADDR_32_GPR_REG_THREE_ADDR;
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b100
    {
      *effectiveAddr = ADDR_32_GPR_REG_FOUR_ADDR;
    }
    else if( (modRmByte >> 2 & 1) && !(modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b101
    {
      *effectiveAddr = ADDR_32_GPR_REG_FIVE_ADDR;
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && !(modRmByte & 1)) // R/M: 0b110
    {
      *effectiveAddr = ADDR_32_GPR_REG_SIX_ADDR;
    }
    else if( (modRmByte >> 2 & 1) && (modRmByte >> 1 & 1) && (modRmByte & 1)) // R/M: 0b111
    {
      *effectiveAddr = ADDR_32_GPR_REG_SEVEN_ADDR;
    }
  }

  /* Extract the register value from the modRM byte. */
  // 0b000
  if( !(modRmByte >> 5 & 1) && !(modRmByte >> 4 & 1) && !(modRmByte >> 3 & 1))
  {
    *reg = GPR_REG_ZERO;
  }
  // 0b001
  else if( !(modRmByte >> 5 & 1) && !(modRmByte >> 4 & 1) && (modRmByte >> 3 & 1))
  {
    *reg = GPR_REG_ONE;
  }
  // 0b010
  else if( !(modRmByte >> 5 & 1) && (modRmByte >> 4 & 1) && !(modRmByte >> 3 & 1))
  {
    *reg = GPR_REG_TWO;
  }
  // 0b011
  else if( !(modRmByte >> 5 & 1) && (modRmByte >> 4 & 1) && (modRmByte >> 3 & 1))
  {
    *reg = GPR_REG_THREE;
  }
  // 0b100
  else if((modRmByte >> 5 & 1) && !(modRmByte >> 4 & 1) && !(modRmByte >> 3 & 1))
  {
    *reg = GPR_REG_FOUR;
  }
  // 0b101
  else if((modRmByte >> 5 & 1) && !(modRmByte >> 4 & 1) && (modRmByte >> 3 & 1))
  {
    *reg = GPR_REG_FIVE;
  }
  // 0b110
  else if((modRmByte >> 5 & 1) && (modRmByte >> 4 & 1) && !(modRmByte >> 3 & 1))
  {
    *reg = GPR_REG_SIX;
  }
  // 0b111
  else if((modRmByte >> 5 & 1) && (modRmByte >> 4 & 1) && (modRmByte >> 3 & 1))
  {
    *reg = GPR_REG_SEVEN;
  }

  return ERR_NONE;
}

/*
 *  7      6 5     3 2     0
 *  | scale | index | base |
*/

static int8_t getSIBData(uint8_t SIBbyte, uint8_t* scaledIndex, uint8_t* base)
{
  if(scaledIndex == NULL || base == NULL)
  {
    return ERR_NULL_ARGUMENT;
  }

  /* Get the effective address. */
  if( !(SIBbyte >> 7 & 1) && !(SIBbyte >> 6 & 1))   // Mod: 0b00
  {
    if( !(SIBbyte >> 5 & 1) && !(SIBbyte >> 4 & 1) && !(SIBbyte >> 3 & 1)) // R/M: 0b000
    {
      *scaledIndex = SCALED_INDEX__EAX__;
    }
    else if( !(SIBbyte >> 5 & 1) && !(SIBbyte >> 4 & 1) && (SIBbyte >> 3 & 1)) // R/M: 0b001
    {
      *scaledIndex = SCALED_INDEX__ECX__;
    }
    else if( !(SIBbyte >> 5 & 1) && (SIBbyte >> 4 & 1) && !(SIBbyte >> 3 & 1)) // R/M: 0b010
    {
      *scaledIndex = SCALED_INDEX__EDX__;
    }
    else if( !(SIBbyte >> 5 & 1) && (SIBbyte >> 4 & 1) && (SIBbyte >> 3 & 1)) // R/M: 0b011
    {
      *scaledIndex = SCALED_INDEX__EBX__;
    }
    else if( (SIBbyte >> 5 & 1) && !(SIBbyte >> 4 & 1) && !(SIBbyte >> 3 & 1)) // R/M: 0b100
    {
      *scaledIndex = SCALED_INDEX_NONE;
    }
    else if( (SIBbyte >> 5 & 1) && !(SIBbyte >> 4 & 1) && (SIBbyte >> 3 & 1)) // R/M: 0b101
    {
      *scaledIndex = SCALED_INDEX__EBP__;
    }
    else if( (SIBbyte >> 5 & 1) && (SIBbyte >> 4 & 1) && !(SIBbyte >> 3 & 1)) // R/M: 0b110
    {
      *scaledIndex = SCALED_INDEX__ESI__;
    }
    else if( (SIBbyte >> 5 & 1) && (SIBbyte >> 4 & 1) && (SIBbyte >> 3 & 1)) // R/M: 0b111
    {
      *scaledIndex = SCALED_INDEX__EDI__;
    }
  }

  else if( !(SIBbyte >> 7 & 1) && (SIBbyte >> 6 & 1)) // Mod: 0b01
  {
    if( !(SIBbyte >> 5 & 1) && !(SIBbyte >> 4 & 1) && !(SIBbyte >> 3 & 1)) // R/M: 0b000
    {
      *scaledIndex = SCALED_INDEX__EAX_MULT_TWO__;
    }
    else if( !(SIBbyte >> 5 & 1) && !(SIBbyte >> 4 & 1) && (SIBbyte >> 3 & 1)) // R/M: 0b001
    {
      *scaledIndex = SCALED_INDEX__ECX_MULT_TWO__;
    }
    else if( !(SIBbyte >> 5 & 1) && (SIBbyte >> 4 & 1) && !(SIBbyte >> 3 & 1)) // R/M: 0b010
    {
      *scaledIndex = SCALED_INDEX__EDX_MULT_TWO__;
    }
    else if( !(SIBbyte >> 5 & 1) && (SIBbyte >> 4 & 1) && (SIBbyte >> 3 & 1)) // R/M: 0b011
    {
      *scaledIndex = SCALED_INDEX__EBX_MULT_TWO__;
    }
    else if( (SIBbyte >> 5 & 1) && !(SIBbyte >> 4 & 1) && !(SIBbyte >> 3 & 1)) // R/M: 0b100
    {
      *scaledIndex = SCALED_INDEX_NONE;
    }
    else if( (SIBbyte >> 5 & 1) && !(SIBbyte >> 4 & 1) && (SIBbyte >> 3 & 1)) // R/M: 0b101
    {
      *scaledIndex = SCALED_INDEX__EBP_MULT_TWO__;
    }
    else if( (SIBbyte >> 5 & 1) && (SIBbyte >> 4 & 1) && !(SIBbyte >> 3 & 1)) // R/M: 0b110
    {
      *scaledIndex = SCALED_INDEX__ESI_MULT_TWO__;
    }
    else if( (SIBbyte >> 5 & 1) && (SIBbyte >> 4 & 1) && (SIBbyte >> 3 & 1)) // R/M: 0b111
    {
      *scaledIndex = SCALED_INDEX__EDI_MULT_TWO__;
    }
  }

  else if( (SIBbyte >> 7 & 1) && !(SIBbyte >> 6 & 1)) // Mod: 0b10
  {
    if( !(SIBbyte >> 5 & 1) && !(SIBbyte >> 4 & 1) && !(SIBbyte >> 3 & 1)) // R/M: 0b000
    {
      *scaledIndex = SCALED_INDEX__EAX_MULT_FOUR__;
    }
    else if( !(SIBbyte >> 5 & 1) && !(SIBbyte >> 4 & 1) && (SIBbyte >> 3 & 1)) // R/M: 0b001
    {
      *scaledIndex = SCALED_INDEX__ECX_MULT_FOUR__;
    }
    else if( !(SIBbyte >> 5 & 1) && (SIBbyte >> 4 & 1) && !(SIBbyte >> 3 & 1)) // R/M: 0b010
    {
      *scaledIndex = SCALED_INDEX__EDX_MULT_FOUR__;
    }
    else if( !(SIBbyte >> 5 & 1) && (SIBbyte >> 4 & 1) && (SIBbyte >> 3 & 1)) // R/M: 0b011
    {
      *scaledIndex = SCALED_INDEX__EBX_MULT_FOUR__;
    }
    else if( (SIBbyte >> 5 & 1) && !(SIBbyte >> 4 & 1) && !(SIBbyte >> 3 & 1)) // R/M: 0b100
    {
      *scaledIndex = SCALED_INDEX_NONE;
    }
    else if( (SIBbyte >> 5 & 1) && !(SIBbyte >> 4 & 1) && (SIBbyte >> 3 & 1)) // R/M: 0b101
    {
      *scaledIndex = SCALED_INDEX__EBP_MULT_FOUR__;
    }
    else if( (SIBbyte >> 5 & 1) && (SIBbyte >> 4 & 1) && !(SIBbyte >> 3 & 1)) // R/M: 0b110
    {
      *scaledIndex = SCALED_INDEX__ESI_MULT_FOUR__;
    }
    else if( (SIBbyte >> 5 & 1) && (SIBbyte >> 4 & 1) && (SIBbyte >> 3 & 1)) // R/M: 0b111
    {
      *scaledIndex = SCALED_INDEX__EDI_MULT_FOUR__;
    }
  }

  else if( (SIBbyte >> 7 & 1) && (SIBbyte >> 6 & 1))  // Mod: 0b11
  {

    if( !(SIBbyte >> 5 & 1) && !(SIBbyte >> 4 & 1) && !(SIBbyte >> 3 & 1)) // R/M: 0b000
    {
      *scaledIndex = SCALED_INDEX__EAX_MULT_EIGHT__;
    }
    else if( !(SIBbyte >> 5 & 1) && !(SIBbyte >> 4 & 1) && (SIBbyte >> 3 & 1)) // R/M: 0b001
    {
      *scaledIndex = SCALED_INDEX__ECX_MULT_EIGHT__;
    }
    else if( !(SIBbyte >> 5 & 1) && (SIBbyte >> 4 & 1) && !(SIBbyte >> 3 & 1)) // R/M: 0b010
    {
      *scaledIndex = SCALED_INDEX__EDX_MULT_EIGHT__;
    }
    else if( !(SIBbyte >> 5 & 1) && (SIBbyte >> 4 & 1) && (SIBbyte >> 3 & 1)) // R/M: 0b011
    {
      *scaledIndex = SCALED_INDEX__EBX_MULT_EIGHT__;
    }
    else if( (SIBbyte >> 5 & 1) && !(SIBbyte >> 4 & 1) && !(SIBbyte >> 3 & 1)) // R/M: 0b100
    {
      *scaledIndex = SCALED_INDEX_NONE;
    }
    else if( (SIBbyte >> 5 & 1) && !(SIBbyte >> 4 & 1) && (SIBbyte >> 3 & 1)) // R/M: 0b101
    {
      *scaledIndex = SCALED_INDEX__EBP_MULT_EIGHT__;
    }
    else if( (SIBbyte >> 5 & 1) && (SIBbyte >> 4 & 1) && !(SIBbyte >> 3 & 1)) // R/M: 0b110
    {
      *scaledIndex = SCALED_INDEX__ESI_MULT_EIGHT__;
    }
    else if( (SIBbyte >> 5 & 1) && (SIBbyte >> 4 & 1) && (SIBbyte >> 3 & 1)) // R/M: 0b111
    {
      *scaledIndex = SCALED_INDEX__EDI_MULT_EIGHT__;
    }
  }

  if( !(SIBbyte >> 2 & 1) && !(SIBbyte >> 1 & 1) && !(SIBbyte & 1)) // 0b000
  {
    *base = GPR_REG_ZERO;
  }
  else if( !(SIBbyte >> 2 & 1) && !(SIBbyte >> 1 & 1) && (SIBbyte & 1)) // 0b001
  {
    *base = GPR_REG_ONE;
  }
  else if( !(SIBbyte >> 2 & 1) && (SIBbyte >> 1 & 1) && !(SIBbyte & 1)) // 0b010
  {
    *base = GPR_REG_TWO;
  }
  else if( !(SIBbyte >> 2 & 1) && (SIBbyte >> 1 & 1) && (SIBbyte & 1)) // 0b011
  {
    *base = GPR_REG_THREE;
  }
  else if( (SIBbyte >> 2 & 1) && !(SIBbyte >> 1 & 1) && !(SIBbyte & 1)) // 0b100
  {
    *base = GPR_REG_FOUR;
  }
  else if( (SIBbyte >> 2 & 1) && !(SIBbyte >> 1 & 1) && (SIBbyte & 1)) // 0b101
  {
    *base = GPR_REG_FIVE;
  }
  else if( (SIBbyte >> 2 & 1) && (SIBbyte >> 1 & 1) && !(SIBbyte & 1)) // 0b110
  {
    *base = GPR_REG_SIX;
  }
  else if( (SIBbyte >> 2 & 1) && (SIBbyte >> 1 & 1) && (SIBbyte & 1)) // 0b111
  {
    *base = GPR_REG_SEVEN;
  }
  return ERR_NONE;
}

int8_t getREXData(uint8_t REXByte, uint8_t* REXw, uint8_t* REXr, uint8_t* REXx, uint8_t* REXb)
{
  if(REXw == NULL || REXr == NULL || REXx == NULL || REXb == NULL)
  {
    return ERR_NULL_ARGUMENT;
  }
  /* Check it's actually a valid REX byte. */
  if((REXByte & REX_PREFIX_VALID_PREFIX) != REX_PREFIX_VALID_PREFIX) // 0b01000000
  {
    return ERR_INVALID_ARGUMENT;
  }

  *REXw = (REXByte >> 3 & 1) ? REX_PREFIX_64_BIT_OPERAND : REX_PREFIX_NOT_64_BIT_OPERAND;
  *REXr = (REXByte >> 2 & 1) ? REX_PREFIX_REGISTER_EXTENDED : REX_PREFIX_NOT_REGISTER_EXTENDED;
  *REXx = (REXByte >> 1 & 1) ? REX_PREFIX_SIB_INDEX_EXTENDED : REX_PREFIX_NOT_SIB_INDEX_EXTENDED;  
  *REXb = (REXByte & 1)      ? REX_PREFIX_SIB_BASE_EXTENDED : REX_PREFIX_NOT_SIB_BASE_EXTENDED;  

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
  assert(effectiveAddr == ADDR_16___BX_ADD_SI__);
  assert(reg == GPR_REG_ZERO);

  err = getModRmData16Bit(0x48, &effectiveAddr, &reg);
  assert(err == ERR_NONE);
  assert(effectiveAddr == ADDR_16___BX_ADD_SI__ADD_DISP8_CUBED);
  assert(reg == GPR_REG_ONE);

  err = getModRmData16Bit(0x92, &effectiveAddr, &reg);
  assert(err == ERR_NONE);
  assert(effectiveAddr == ADDR_16___BP_ADD_SI__ADD_DISP16);
  assert(reg == GPR_REG_TWO);

  err = getModRmData16Bit(0xDA, &effectiveAddr, &reg);
  assert(err == ERR_NONE);
  assert(effectiveAddr == ADDR_16_GPR_REG_TWO_ADDR);
  assert(reg == GPR_REG_THREE);

  err = getModRmData16Bit(0xA5, &effectiveAddr, &reg);
  assert(err == ERR_NONE);
  assert(effectiveAddr == ADDR_16___DI__ADD_DISP16);
  assert(reg == GPR_REG_FOUR);

  err = getModRmData16Bit(0x6F, &effectiveAddr, &reg);
  assert(err == ERR_NONE);
  assert(effectiveAddr == ADDR_16___BX__ADD_DISP8);
  assert(reg == GPR_REG_FIVE);

  err = getModRmData16Bit(0x35, &effectiveAddr, &reg);
  assert(err == ERR_NONE);
  assert(effectiveAddr == ADDR_16___DI__);
  assert(reg == GPR_REG_SIX);

  err = getModRmData16Bit(0x3B, &effectiveAddr, &reg);
  assert(err == ERR_NONE);
  assert(effectiveAddr == ADDR_16___BP_ADD_DI__);
  assert(reg == GPR_REG_SEVEN);
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

static void test_getModRmData32Bit_legalValues()
{
  uint8_t effectiveAddr = 0;
  uint8_t reg = 1; // Set this to a value other than zero for first call.
  int8_t err = ERR_NONE;

  err = getModRmData32Bit(0x00, &effectiveAddr, &reg);
  assert(err == ERR_NONE);
  assert(effectiveAddr == ADDR_32__EAX__);
  assert(reg == GPR_REG_ZERO);

  err = getModRmData32Bit(0x48, &effectiveAddr, &reg);
  assert(err == ERR_NONE);
  assert(effectiveAddr == ADDR_32__EAX__ADD_DISP8_CUBED);
  assert(reg == GPR_REG_ONE);

  err = getModRmData32Bit(0x92, &effectiveAddr, &reg);
  assert(err == ERR_NONE);
  assert(effectiveAddr == ADDR_32__EDX__ADD_DISP32);
  assert(reg == GPR_REG_TWO);

  err = getModRmData32Bit(0xDA, &effectiveAddr, &reg);
  assert(err == ERR_NONE);
  assert(effectiveAddr == ADDR_32_GPR_REG_TWO_ADDR);
  assert(reg == GPR_REG_THREE);
}

static void test_getSIBData_legalValues()
{
  uint8_t scaledIndex = 0;
  uint8_t base = 1; // Set this to a value other than zero for first call.
  int8_t err = ERR_NONE;

  err = getSIBData(0x08, &scaledIndex, &base);
  assert(err == ERR_NONE);
  assert(scaledIndex == SCALED_INDEX__ECX__);
  assert(base == GPR_REG_ZERO);

  err = getSIBData(0x41, &scaledIndex, &base);
  assert(err == ERR_NONE);
  assert(scaledIndex == SCALED_INDEX__EAX_MULT_TWO__);
  assert(base == GPR_REG_ONE);

  err = getSIBData(0x62, &scaledIndex, &base);
  assert(err == ERR_NONE);
  assert(scaledIndex == SCALED_INDEX_NONE);
  assert(base == GPR_REG_TWO);

  err = getSIBData(0xAB, &scaledIndex, &base);
  assert(err == ERR_NONE);
  assert(scaledIndex == SCALED_INDEX__EBP_MULT_FOUR__);
  assert(base == GPR_REG_THREE);

  err = getSIBData(0xFC, &scaledIndex, &base);
  assert(err == ERR_NONE);
  assert(scaledIndex == SCALED_INDEX__EDI_MULT_EIGHT__);
  assert(base == GPR_REG_FOUR);

  err = getSIBData(0xF5, &scaledIndex, &base);
  assert(err == ERR_NONE);
  assert(scaledIndex == SCALED_INDEX__ESI_MULT_EIGHT__);
  assert(base == GPR_REG_FIVE);

  err = getSIBData(0xEE, &scaledIndex, &base);
  assert(err == ERR_NONE);
  assert(scaledIndex == SCALED_INDEX__EBP_MULT_EIGHT__);
  assert(base == GPR_REG_SIX);

  err = getSIBData(0xD7, &scaledIndex, &base);
  assert(err == ERR_NONE);
  assert(scaledIndex == SCALED_INDEX__EDX_MULT_EIGHT__);
  assert(base == GPR_REG_SEVEN);
}

/* Test all legal values: 0x40 - 0x4F*/
static void test_getREXData_legalValues()
{
  int8_t err = ERR_NONE;
  uint8_t rexW = 0, rexR = 0, rexX = 0, rexB = 0;

  err = getREXData(0x40, &rexW, &rexR, &rexX, &rexB);
  assert(err == ERR_NONE);
  assert(rexW == REX_PREFIX_NOT_64_BIT_OPERAND);
  assert(rexR == REX_PREFIX_NOT_REGISTER_EXTENDED);
  assert(rexX == REX_PREFIX_NOT_SIB_INDEX_EXTENDED);
  assert(rexB == REX_PREFIX_NOT_SIB_BASE_EXTENDED);

  err = getREXData(0x41, &rexW, &rexR, &rexX, &rexB);
  assert(err == ERR_NONE);
  assert(rexW == REX_PREFIX_NOT_64_BIT_OPERAND);
  assert(rexR == REX_PREFIX_NOT_REGISTER_EXTENDED);
  assert(rexX == REX_PREFIX_NOT_SIB_INDEX_EXTENDED);
  assert(rexB == REX_PREFIX_SIB_BASE_EXTENDED);

  err = getREXData(0x42, &rexW, &rexR, &rexX, &rexB);
  assert(err == ERR_NONE);
  assert(rexW == REX_PREFIX_NOT_64_BIT_OPERAND);
  assert(rexR == REX_PREFIX_NOT_REGISTER_EXTENDED);
  assert(rexX == REX_PREFIX_SIB_INDEX_EXTENDED);
  assert(rexB == REX_PREFIX_NOT_SIB_BASE_EXTENDED);

  err = getREXData(0x43, &rexW, &rexR, &rexX, &rexB);
  assert(err == ERR_NONE);
  assert(rexW == REX_PREFIX_NOT_64_BIT_OPERAND);
  assert(rexR == REX_PREFIX_NOT_REGISTER_EXTENDED);
  assert(rexX == REX_PREFIX_SIB_INDEX_EXTENDED);
  assert(rexB == REX_PREFIX_SIB_BASE_EXTENDED);

  err = getREXData(0x44, &rexW, &rexR, &rexX, &rexB);
  assert(err == ERR_NONE);
  assert(rexW == REX_PREFIX_NOT_64_BIT_OPERAND);
  assert(rexR == REX_PREFIX_REGISTER_EXTENDED);
  assert(rexX == REX_PREFIX_NOT_SIB_INDEX_EXTENDED);
  assert(rexB == REX_PREFIX_NOT_SIB_BASE_EXTENDED);

  err = getREXData(0x45, &rexW, &rexR, &rexX, &rexB);
  assert(err == ERR_NONE);
  assert(rexW == REX_PREFIX_NOT_64_BIT_OPERAND);
  assert(rexR == REX_PREFIX_REGISTER_EXTENDED);
  assert(rexX == REX_PREFIX_NOT_SIB_INDEX_EXTENDED);
  assert(rexB == REX_PREFIX_SIB_BASE_EXTENDED);
}

// TEST SUITE
void x64_DisassemblyTestSuite()
{
  test_getModRmData16Bit_legalValues();
  test_getModRmData16Bit_nullArguments();

  test_getModRmData32Bit_legalValues();

  test_getSIBData_legalValues();

  test_getREXData_legalValues();
}

#endif /* UNITTEST */