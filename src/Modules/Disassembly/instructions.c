#include "./x64_disassembly.h"

IntelX64Instruction_T instructions[]
{
/* Opcode,         Mnemonic,          64-bit mode,      legacy mode */
  {"\xFF",       "PUSH r/m16",           true,             true}, // ModR/M byte gives operand
  {"\xFF",       "PUSH r/m32",           false,            true},
  {"\xFF",       "PUSH r/m64",           true,             false},
};