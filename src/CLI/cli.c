#include "../Modules/ELFinfo/elfinfo.h"
#include "../Modules/Dynamic/elfdynamic.h"
#include "../FileOperations/fileOps.h"

#define TEST32 "/home/calum/Test_Files/while32"
#define TEST64 "/home/calum/Test_Files/while64"

#define TEST32_2 "/home/calum/Test_Bins/while2_32"
#define TEST64_2 "/home/calum/Test_Bins/while2_64"

#define TEST_STRINGS "/home/calum/Test_Files/strings"

int main(int argc, char *argv[], char *envp[])
{
    // enum BITS* arch;
    // uint64_t fileSz;
    // char* pMem;

    // pMem = mapELFToMemory(TEST64, arch, &fileSz);

    // uint64_t symAdd = getSymbolAddr(pMem, "test");

    // printf("Address of main: 0x%08x\n", symAdd);
    scanForStrings(TEST32, 3);
    return 0;
}

