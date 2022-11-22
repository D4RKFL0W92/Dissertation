#include "../Modules/ELFinfo/elfinfo.h"
#include "../Modules/Dynamic/elfdynamic.h"
#include "../FileOperations/fileOps.h"
#include "../Memory/turtle_memory.h"
#include "../Help/help.h"

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
        printf(helpMenu);
        exit(-1);
    }

    for(int i = 1; i < argc-1; i++)
    {
        if(!strncmp(argv[i], "-sha1", 5))
        {
            if(printSHA1OfFile(argv[argc-1]) == FAILED)
            {
                printf("Unable to calculate hash for %s.\n", argv[argc-1]);
                exit(-1);
            }
        }
        if(!strncmp(argv[i], "-E", 2))
        {
            ELF64_EXECUTABLE_HANDLE_T executableHandle;
            FILE_HANDLE_T fileHandle;
            if(mapFileToStruct(argv[argc-1], &fileHandle) == FAILED)
            {
                printf("Unable map %s into memory\n", argv[argc-1]);
                exit(-1);
            }

            if(printElfInfoVerbose(&fileHandle) == FAILED)
            {
                printf("Unable to get ELF info from %s\n", argv[argc-1]);
                exit(-1);
            }

            /* Unmap the file. */
            munmap(fileHandle.p_data, fileHandle.st.st_size);
        }
        if(!strncmp(argv[i], "-hd", 3))
        {
            uint64_t start = atol(argv[i+1]);
            uint64_t uCount = atoi(argv[i+2]);
            
            dumpHexBytes(argv[argc-1], start, uCount);
        }
    }
    
    return 0;
}

