#ifndef _DISAS_
#define _DISAS_

#include "../../Types/turtle_types.h"

typedef struct IntelX64Instruction
{
  uint8_t  legacyPrefix;      /* Optional */
  uint8_t  rexPrefix;         /* Optional: used in 64bit mode for addressing. */
  uint8_t  vexPrefix[3];      /* If a VEX prefix is present, the REX prefix is not used. */
  uint8_t  opcode[3];
  uint8_t  modRmByte;
  uint8_t  sibByte;
  uint32_t displacement;
  uint32_t immediateData;
} IntelX64Instruction_T;

/* Definitions of optional instruction prefixes. */
/* Group 1 Prefixes */
#define INST_PREFIX_LOCK            0xF0
#define INST_PREFIX_REPNE_REPNZ     0xF2
#define INST_PREFIX_REPE_REPZ       0xF3
/*
 * BND prefix is encoded using F2H if the following conditions are true:
 * - CPUID.(EAX=07H, ECX=0):EBX.MPX[bit 14] is set.
 * - BNDCFGU.EN and/or IA32_BNDCFGS.EN is set.
 * - When the F2 prefix precedes a near CALL, a near RET, a near JMP, a short Jcc, or a near Jcc instruction
*/
#define INST_PREFIX_BND             0xF3


/* Group 2 */
/* Segment override prefixes: */
#define SEG_PREFIX_CS               0x2E
#define SEG_PREFIX_ES               0x26
#define SEG_PREFIX_SS               0x36
#define SEG_PREFIX_DS               0x3E
#define SEG_PREFIX_FS               0x64
#define SEG_PREFIX_GS               0x65
/* Branch hints: */
#define BRANCH_HINT_PREFIX_NOTTAKEN 0x2E // Only used with Jcc instruction.
#define BRANCH_HINT_PREFIX_TAKEN    0x3E // Only used with Jcc instruction.


/* Group 3 */
/*
 * Operand-size override prefix is encoded using 66H
 * (66H is also used as a mandatory prefix for some instructions)
*/
#define OPERAND_SZ_OVERRIDE_PREFIX  0x66


/* Group 4 */
/* Address size override: */
#define ADDRESS_SZ_OVERRIDE_PREFIX  0x67


/*
 * Definitions used in extracting addressing
 * mode from Mod/RM and SIB bytes.
*/
#define SIB_BYTE_IS_EXPECTED            1
#define SIB_BYTE_NOT_EXPECTED           0

/* Definitions of 16-bit effective address options. */

// Mod 0b00 effective address options.
#define ADDR_16___BX_ADD_SI__                      0 // [BX+SI]             R/M: 0b000
#define ADDR_16___BX_ADD_DI__                      1 // [BX+DI]             R/M: 0b001
#define ADDR_16___BP_ADD_SI__                      2 // [BP+SI]             R/M: 0b010
#define ADDR_16___BP_ADD_DI__                      3 // [BP+DI]             R/M: 0b011
#define ADDR_16___SI__                             4 // [SI]                R/M: 0b100
#define ADDR_16___DI__                             5 // [DI]                R/M: 0b101
#define ADDR_16_DISP_16_SQ                         6 // displacement16^2    R/M: 0b110
#define ADDR_16___BX__                             7 // [BX]                R/M: 0b111

// Mod 0b01 effective address options.
#define ADDR_16___BX_ADD_SI__ADD_DISP8_CUBED       8 // [BX+SI]+disp8^3     R/M: 0b000
#define ADDR_16___BX_ADD_DI__ADD_DISP8             9 // [BX+DI]+disp8       R/M: 0b001
#define ADDR_16___BP_ADD_SI__ADD_DISP8            10 // [BP+SI]+disp8       R/M: 0b010
#define ADDR_16___BP_ADD_DI__ADD_DISP8            11 // [BP+DI]+disp8       R/M: 0b011
#define ADDR_16___SI__ADD_DISP8                   12 // [SI]+disp8          R/M: 0b100
#define ADDR_16___DI__ADD_DISP8                   13 // [DI]+disp8          R/M: 0b101
#define ADDR_16___BP__ADD_DISP8                   14 // [BP]+disp8          R/M: 0b110
#define ADDR_16___BX__ADD_DISP8                   15 // [BX]+disp8          R/M: 0b111

// Mod 0b10 effective address options.
#define ADDR_16___BX_ADD_SI__ADD_DISP16           16 // [BX+SI]+disp16      R/M: 0b000
#define ADDR_16___BX_ADD_DI__ADD_DISP16           17 // [BX+DI]+disp16      R/M: 0b001
#define ADDR_16___BP_ADD_SI__ADD_DISP16           18 // [BP+SI]+disp16      R/M: 0b010
#define ADDR_16___BP_ADD_DI__ADD_DISP16           19 // [BP+DI]+disp16      R/M: 0b011
#define ADDR_16___SI__ADD_DISP16                  20 // [SI]+disp16         R/M: 0b100
#define ADDR_16___DI__ADD_DISP16                  21 // [DI]+disp16         R/M: 0b101
#define ADDR_16___BP__ADD_DISP16                  22 // [BP]+disp16         R/M: 0b110
#define ADDR_16___BX__ADD_DISP16                  23 // [BX]+disp16         R/M: 0b111

// Mod 0b11 effective address options.
#define ADDR_16_GPR_REG_ZERO_ADDR                 24 // EAX/AX/AL/MM0/XMM0  R/M: 0b000
#define ADDR_16_GPR_REG_ONE_ADDR                  25 // ECX/CX/CL/MM1/XMM1  R/M: 0b001
#define ADDR_16_GPR_REG_TWO_ADDR                  26 // EDX/DX/DL/MM2/XMM2  R/M: 0b010
#define ADDR_16_GPR_REG_THREE_ADDR                27 // EBX/BX/BL/MM3/XMM3  R/M: 0b011
#define ADDR_16_GPR_REG_FOUR_ADDR                 28 // ESP/SP/AH/MM4/XMM4  R/M: 0b100
#define ADDR_16_GPR_REG_FIVE_ADDR                 29 // EBP/BP/CH/MM5/XMM5  R/M: 0b101
#define ADDR_16_GPR_REG_SIX_ADDR                  30 // ESI/SI/DH/MM6/XMM6  R/M: 0b110
#define ADDR_16_GPR_REG_SEVEN_ADDR                31 // EDI/DI/BH/MM7/XMM7  R/M: 0b111

/* Definitions of 32-bit effective address options. */
// Mod 0b00 effective address options.
#define ADDR_32__EAX__                            32 // [EAX]               R/M: 0b000
#define ADDR_32__ECX__                            33 // [ECX]               R/M: 0b001
#define ADDR_32__EDX__                            34 // [EDX]               R/M: 0b010
#define ADDR_32__EBX__                            35 // [EBX]               R/M: 0b011
#define ADDR_32_SIB                               36 // [--][--]            R/M: 0b100
#define ADDR_32_DISP32_SQUARED                    37 // [DI]                R/M: 0b101
#define ADDR_32__ESI__                            38 // [ESI]               R/M: 0b110
#define ADDR_32__EDI__                            39 // [BX]                R/M: 0b111

// Mod 0b01 effective address options.
#define ADDR_32__EAX__ADD_DISP8_CUBED             40 // [EAX]+disp8^3       R/M: 0b000
#define ADDR_32__ECX__ADD_DISP8                   41 // [ECX]+disp8         R/M: 0b001
#define ADDR_32__EDX__ADD_DISP8                   42 // [EDX]+disp8         R/M: 0b010
#define ADDR_32__EBX__ADD_DISP8                   43 // [EBX]+disp8         R/M: 0b011
#define ADDR_32_SIB_ADD_DISP8                     44 // [--]+disp8          R/M: 0b100
#define ADDR_32__EBP__ADD_DISP8                   45 // [EBP]+disp8         R/M: 0b101
#define ADDR_32__ESI__ADD_DISP8                   46 // [ESI]+disp8         R/M: 0b110
#define ADDR_32__EDI__ADD_DISP8                   47 // [EDI]+disp8         R/M: 0b111

// Mod 0b10 effective address options.
#define ADDR_32__EAX__ADD_DISP32                  48 // [EAX]+disp16        R/M: 0b000
#define ADDR_32__ECX__ADD_DISP32                  49 // [ECX]+disp16        R/M: 0b001
#define ADDR_32__EDX__ADD_DISP32                  50 // [EDX]+disp16        R/M: 0b010
#define ADDR_32__EBX__ADD_DISP32                  51 // [EBX]+disp16        R/M: 0b011
#define ADDR_32_SIB_ADD_DISP32                    52 // [--]+disp16         R/M: 0b100
#define ADDR_32__EBP__ADD_DISP32                  53 // [EBP]+disp16        R/M: 0b101
#define ADDR_32__ESI__ADD_DISP32                  54 // [ESI]+disp16        R/M: 0b110
#define ADDR_32__EDI__ADD_DISP32                  55 // [EDI]+disp16        R/M: 0b111

// Mod 0b11 effective address options.
#define ADDR_32_GPR_REG_ZERO_ADDR                 56 // EAX/AX/AL/MM0/XMM0  R/M: 0b000
#define ADDR_32_GPR_REG_ONE_ADDR                  57 // ECX/CX/CL/MM1/XMM1  R/M: 0b001
#define ADDR_32_GPR_REG_TWO_ADDR                  58 // EDX/DX/DL/MM2/XMM2  R/M: 0b010
#define ADDR_32_GPR_REG_THREE_ADDR                59 // EBX/BX/BL/MM3/XMM3  R/M: 0b011
#define ADDR_32_GPR_REG_FOUR_ADDR                 60 // ESP/SP/AH/MM4/XMM4  R/M: 0b100
#define ADDR_32_GPR_REG_FIVE_ADDR                 61 // EBP/BP/CH/MM5/XMM5  R/M: 0b101
#define ADDR_32_GPR_REG_SIX_ADDR                  62 // ESI/SI/DH/MM6/XMM6  R/M: 0b110
#define ADDR_32_GPR_REG_SEVEN_ADDR                63 // EDI/DI/BH/MM7/XMM7  R/M: 0b111


/* Definitions for scaled index. */
/*
 *  format of SIB byte
 * 
 *  7      6 5     3 2     0
 *  | scale | index | base |
*/

#define SCALED_INDEX__EAX__                         0 // [EAX]  R/M: 0b000
#define SCALED_INDEX__ECX__                         1 // [ECX]  R/M: 0b001
#define SCALED_INDEX__EDX__                         2 // [EDX]  R/M: 0b010
#define SCALED_INDEX__EBX__                         3 // [EBX]  R/M: 0b011
#define SCALED_INDEX_NONE                           4 // none   R/M: 0b100
#define SCALED_INDEX__EBP__                         5 // [EBP]  R/M: 0b101
#define SCALED_INDEX__ESI__                         6 // [ESI]  R/M: 0b110
#define SCALED_INDEX__EDI__                         7 // [EDI]  R/M: 0b111

#define SCALED_INDEX__EAX_MULT_TWO__                8 // [EAX*2]  R/M: 0b000
#define SCALED_INDEX__ECX_MULT_TWO__                9 // [ECX*2]  R/M: 0b001
#define SCALED_INDEX__EDX_MULT_TWO__               10 // [EDX*2]  R/M: 0b010
#define SCALED_INDEX__EBX_MULT_TWO__               11 // [EBX*2]  R/M: 0b011
                                                      // none     R/M: 0b100
#define SCALED_INDEX__EBP_MULT_TWO__               13 // [EBP*2]  R/M: 0b101
#define SCALED_INDEX__ESI_MULT_TWO__               14 // [ESI*2]  R/M: 0b110
#define SCALED_INDEX__EDI_MULT_TWO__               15 // [EDI*2]  R/M: 0b111

#define SCALED_INDEX__EAX_MULT_FOUR__              16 // [EAX*4]  R/M: 0b000
#define SCALED_INDEX__ECX_MULT_FOUR__              17 // [ECX*4]  R/M: 0b001
#define SCALED_INDEX__EDX_MULT_FOUR__              18 // [EDX*4]  R/M: 0b010
#define SCALED_INDEX__EBX_MULT_FOUR__              19 // [EBX*4]  R/M: 0b011
                                                      // none     R/M: 0b100
#define SCALED_INDEX__EBP_MULT_FOUR__              21 // [EBP*4]  R/M: 0b101
#define SCALED_INDEX__ESI_MULT_FOUR__              22 // [ESI*4]  R/M: 0b110
#define SCALED_INDEX__EDI_MULT_FOUR__              23 // [EDI*4]  R/M: 0b111

#define SCALED_INDEX__EAX_MULT_EIGHT__              24 // [EAX*8]  R/M: 0b000
#define SCALED_INDEX__ECX_MULT_EIGHT__              25 // [ECX*8]  R/M: 0b001
#define SCALED_INDEX__EDX_MULT_EIGHT__              26 // [EDX*8]  R/M: 0b010
#define SCALED_INDEX__EBX_MULT_EIGHT__              27 // [EBX*8]  R/M: 0b011
                                                       // none     R/M: 0b100
#define SCALED_INDEX__EBP_MULT_EIGHT__              29 // [EBP*8]  R/M: 0b101
#define SCALED_INDEX__ESI_MULT_EIGHT__              30 // [ESI*8]  R/M: 0b110
#define SCALED_INDEX__EDI_MULT_EIGHT__              31 // [EDI*8]  R/M: 0b111

/* REX prefix values */
#define REX_PREFIX_VALID_PREFIX         0x40

/* REX.w values */
#define REX_PREFIX_NOT_64_BIT_OPERAND      0 // Operand size determined by CS.D
#define REX_PREFIX_64_BIT_OPERAND          1

/* REX.r values 
   Extension of the ModR/M reg field
*/
#define REX_PREFIX_NOT_REGISTER_EXTENDED   0
#define REX_PREFIX_REGISTER_EXTENDED       1

/* REX.x values
   Extension of the SIB index field
*/
#define REX_PREFIX_NOT_SIB_INDEX_EXTENDED  0
#define REX_PREFIX_SIB_INDEX_EXTENDED      1

/* REX.b values
   Extension of the ModR/M r/m field, SIB base field,
   or Opcode reg field
*/
#define REX_PREFIX_NOT_SIB_BASE_EXTENDED  0
#define REX_PREFIX_SIB_BASE_EXTENDED      1

/* definitions for general purpose GPR_REGisters */
/* 
 * The GPR_REGister used is determined by the opcode
 * byte and the operand-size attribute
*/

#define GPR_REG_AL    0
#define GPR_REG_AX    0
#define GPR_REG_EAX   0
#define GPR_REG_MM0   0
#define GPR_REG_XMM0  0
#define GPR_REG_ZERO  (GPR_REG_AL|GPR_REG_AX|GPR_REG_EAX|GPR_REG_MM0|GPR_REG_XMM0)

#define GPR_REG_CL    1
#define GPR_REG_CX    1
#define GPR_REG_ECX   1
#define GPR_REG_MM1   1
#define GPR_REG_XMM1  1
#define GPR_REG_ONE   (GPR_REG_CL|GPR_REG_CX|GPR_REG_ECX|GPR_REG_MM1|GPR_REG_XMM1)

#define GPR_REG_DL    2
#define GPR_REG_DX    2
#define GPR_REG_EDX   2
#define GPR_REG_MM2   2
#define GPR_REG_XMM2  2
#define GPR_REG_TWO   (GPR_REG_DL|GPR_REG_DX|GPR_REG_EDX|GPR_REG_MM2|GPR_REG_XMM2)

#define GPR_REG_BL    3
#define GPR_REG_BX    3
#define GPR_REG_EBX   3
#define GPR_REG_MM3   3
#define GPR_REG_XMM3  3
#define GPR_REG_THREE (GPR_REG_BL|GPR_REG_BX|GPR_REG_EBX|GPR_REG_MM3|GPR_REG_XMM3)

#define GPR_REG_AH    4
#define GPR_REG_SP    4
#define GPR_REG_ESP   4
#define GPR_REG_MM4   4
#define GPR_REG_XMM4  4
#define GPR_REG_FOUR  (GPR_REG_AH|GPR_REG_SP|GPR_REG_ESP|GPR_REG_MM4|GPR_REG_XMM4)

#define GPR_REG_CH    5
#define GPR_REG_BP    5
#define GPR_REG_EBP   5
#define GPR_REG_MM5   5
#define GPR_REG_XMM5  5
#define GPR_REG_FIVE  (GPR_REG_CH|GPR_REG_BP|GPR_REG_EBP|GPR_REG_MM5|GPR_REG_XMM5)

#define GPR_REG_DH    6
#define GPR_REG_SI    6
#define GPR_REG_ESI   6
#define GPR_REG_MM6   6
#define GPR_REG_XMM6  6
#define GPR_REG_SIX   (GPR_REG_DH|GPR_REG_SI|GPR_REG_ESI|GPR_REG_MM6|GPR_REG_XMM6)

#define GPR_REG_BH    7
#define GPR_REG_DI    7
#define GPR_REG_EDI   7
#define GPR_REG_MM7   7
#define GPR_REG_XMM7  7
#define GPR_REG_SEVEN (GPR_REG_BH|GPR_REG_DI|GPR_REG_EDI|GPR_REG_MM7|GPR_REG_XMM7)

/* Add opcodes */
#define ADD_AL_IMM    0x04 /* Adds the next byte in sequence to AL GPR_REG. */
#define ADD_AX_IMM    0x05
#define ADD_EAX_IMM   0x05 /* Assuming this is decided by what bytes follow?? */

#ifdef UNITTEST


void x64_DisassemblyTestSuite();

#endif /* UNITTEST */

#endif /* _DISAS_ */