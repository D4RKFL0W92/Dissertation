#include "../Modules/ELFinfo/elfinfo.h"
#include "../Modules/Dynamic/elfdynamic.h"

#define TEST32 "/home/calum/Test_Files/while32"
#define TEST64 "/home/calum/Test_Files/while64"

#define TEST32_2 "/home/calum/Test_Bins/while2_32"
#define TEST64_2 "/home/calum/Test_Bins/while2_64"

int main(int argc, char *argv[], char *envp[])
{
    beginProcessTrace(TEST64_2, argc, argv, envp);
    return 0;
}

