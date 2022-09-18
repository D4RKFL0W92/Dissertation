#include "../Modules/ELFinfo/elfinfo.h"
#include "../Modules/Dynamic/elfdynamic.h"

#define TEST32 "/home/calum/Test_Files/while32"
#define TEST64 "/home/calum/Test_Files/while64"



int main(int argc, char const *argv[], char *envp[])
{
    beginProcessTrace(TEST64, argc, argv, envp);
    return 0;
}

