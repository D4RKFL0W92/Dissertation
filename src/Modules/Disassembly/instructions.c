#include "./x64_disassembly.h"

char opcodes[][3] =
{
    /*
     * In 64-bit mode, direct memory-offset forms of the
     * MOV instruction are extended to specify a 64-bit immediate
     * absolute address. This address is called a moffset.
     * No prefix is needed to specify this 64-bit memory offset. For
     * these MOV instructions, the size of the memory offset
     * follows the address-size default (64 bits in 64-bit mode).
    */
    {"A0"},       /* MOV AL, moffset */
    {"A1"},       /* MOV EAX, moffset */
    {"A2"},       /* MOV moffset, AL */
    {"A3"},       /* MOV moffset, EAX */
};