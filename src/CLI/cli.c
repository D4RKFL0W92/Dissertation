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

    if(clearLogFile(LOG_FILE) == FAILED)
    {
        perror("Unable to clear log file.");
        exit(-1);
    }

    if(argc < 2)
    {
        printf("Usage: < %s > < -opt1 -opt2, ... > < executable >\n", argv[0]);
        exit(-1);
    }

    for(int i = 1; i < argc-1; i++)
    {
        if(!strncmp(argv[i], "-sha1", 5))
        {
            if(printSHA1OfFile(argv[argc-1]) == FAILED)
            {
                printf("Unable to calculate hash for given file.");
                return -1;
            }
        }
    }
    
    return 0;
}

