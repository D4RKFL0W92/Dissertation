#ifndef _DISAS_
#define _DISAS_

#include "../../Types/turtle_types.h"

typedef struct IntelX64Instruction
{
  uint8_t  legacyPrefix;
  uint8_t  rexPrefix;
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
#define __BX_ADD_SI__                      0 // [BX+SI]             R/M: 0b000
#define __BX_ADD_DI__                      1 // [BX+DI]             R/M: 0b001
#define __BP_ADD_SI__                      2 // [BP+SI]             R/M: 0b010
#define __BP_ADD_DI__                      3 // [BP+DI]             R/M: 0b011
#define __SI__                             4 // [SI]                R/M: 0b100
#define __DI__                             5 // [DI]                R/M: 0b101
#define DISP_16_SQ                         6 // displacement16^2    R/M: 0b110
#define __BX__                             7 // [BX]                R/M: 0b111

// Mod 0b01 effective address options.
#define __BX_ADD_SI__ADD_DISP8_CUBED       8 // [BX+SI]+disp8^3     R/M: 0b000
#define __BX_ADD_DI__ADD_DISP8             9 // [BX+DI]+disp8       R/M: 0b001
#define __BP_ADD_SI__ADD_DISP8            10 // [BP+SI]+disp8       R/M: 0b010
#define __BP_ADD_DI__ADD_DISP8            11 // [BP+DI]+disp8       R/M: 0b011
#define __SI__ADD_DISP8                   12 // [SI]+disp8          R/M: 0b100
#define __DI__ADD_DISP8                   13 // [DI]+disp8          R/M: 0b101
#define __BP__ADD_DISP8                   14 // [BP]+disp8          R/M: 0b110
#define __BX__ADD_DISP8                   15 // [BX]+disp8          R/M: 0b111

// Mod 0b10 effective address options.
#define __BX_ADD_SI__ADD_DISP16           16 // [BX+SI]+disp16      R/M: 0b000
#define __BX_ADD_DI__ADD_DISP16           17 // [BX+DI]+disp16      R/M: 0b001
#define __BP_ADD_SI__ADD_DISP16           18 // [BP+SI]+disp16      R/M: 0b010
#define __BP_ADD_DI__ADD_DISP16           19 // [BP+DI]+disp16      R/M: 0b011
#define __SI__ADD_DISP16                  20 // [SI]+disp16         R/M: 0b100
#define __DI__ADD_DISP16                  21 // [DI]+disp16         R/M: 0b101
#define __BP__ADD_DISP16                  22 // [BP]+disp16         R/M: 0b110
#define __BX__ADD_DISP16                  23 // [BX]+disp16         R/M: 0b111

// Mod 0b11 effective address options.
#define REG_ZERO_ADDR                     24 // EAX/AX/AL/MM0/XMM0  R/M: 0b000
#define REG_ONE_ADDR                      25 // ECX/CX/CL/MM1/XMM1  R/M: 0b001
#define REG_TWO_ADDR                      26 // EDX/DX/DL/MM2/XMM2  R/M: 0b010
#define REG_THREE_ADDR                    27 // EBX/BX/BL/MM3/XMM3  R/M: 0b011
#define REG_FOUR_ADDR                     28 // ESP/SP/AH/MM4/XMM4  R/M: 0b100
#define REG_FIVE_ADDR                     29 // EBP/BP/CH/MM5/XMM5  R/M: 0b101
#define REG_SIX_ADDR                      30 // ESI/SI/DH/MM6/XMM6  R/M: 0b110
#define REG_SEVEN_ADDR                    31 // EDI/DI/BH/MM7/XMM7  R/M: 0b111

/* definitions for general purpose registers */
/* 
 * The register used is determined by the opcode
 * byte and the operand-size attribute
*/

#define REG_AL    0
#define REG_AX    0
#define REG_EAX   0
#define REG_MM0   0
#define REG_XMM0  0
#define REG_ZERO  (REG_AL|REG_AX|REG_EAX|REG_MM0|REG_XMM0)

#define REG_CL    1
#define REG_CX    1
#define REG_ECX   1
#define REG_MM1   1
#define REG_XMM1  1
#define REG_ONE   (REG_CL|REG_CX|REG_ECX|REG_MM1|REG_XMM1)

#define REG_DL    2
#define REG_DX    2
#define REG_EDX   2
#define REG_MM2   2
#define REG_XMM2  2
#define REG_TWO   (REG_DL|REG_DX|REG_EDX|REG_MM2|REG_XMM2)

#define REG_BL    3
#define REG_BX    3
#define REG_EBX   3
#define REG_MM3   3
#define REG_XMM3  3
#define REG_THREE (REG_BL|REG_BX|REG_EBX|REG_MM3|REG_XMM3)

#define REG_AH    4
#define REG_SP    4
#define REG_ESP   4
#define REG_MM4   4
#define REG_XMM4  4
#define REG_FOUR  (REG_AH|REG_SP|REG_ESP|REG_MM4|REG_XMM4)

#define REG_CH    5
#define REG_BP    5
#define REG_EBP   5
#define REG_MM5   5
#define REG_XMM5  5
#define REG_FIVE  (REG_CH|REG_BP|REG_EBP|REG_MM5|REG_XMM5)

#define REG_DH    6
#define REG_SI    6
#define REG_ESI   6
#define REG_MM6   6
#define REG_XMM6  6
#define REG_SIX   (REG_DH|REG_SI|REG_ESI|REG_MM6|REG_XMM6)

#define REG_BH    7
#define REG_DI    7
#define REG_EDI   7
#define REG_MM7   7
#define REG_XMM7  7
#define REG_SEVEN (REG_BH|REG_DI|REG_EDI|REG_MM7|REG_XMM7)

/* Add opcodes */
#define ADD_AL_IMM    0x04 /* Adds the next byte in sequence to AL reg. */
#define ADD_AX_IMM    0x05
#define ADD_EAX_IMM   0x05 /* Assuming this is decided by what bytes follow?? */

#ifdef UNITTEST


void x64_DisassemblyTestSuite();

#endif /* UNITTEST */

#endif /* _DISAS_ */