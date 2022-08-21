#include "../Modules/ELFinfo/elfinfo.h"

#define TEST32 "/home/calum/Test_Files/while32"
#define TEST64 "/home/calum/Test_Files/while64"

int main(int argc, char const *argv[])
{
    printELFPhdrs(TEST32);
    return 0;
}
