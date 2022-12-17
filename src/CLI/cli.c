#include <ctype.h>

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
    FILE_HANDLE_T fileHandle;

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
        if(!strcmp(argv[i], "-sha1"))
        {
            if(printSHA1OfFile(argv[argc-1]) == FAILED)
            {
                printf("Unable to calculate hash for %s.\n", argv[argc-1]);
                exit(-1);
            }
        }
        if(!strcmp(argv[i], "-E"))
        {
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
        if(!strcmp(argv[i], "-hd"))
        {
            uint64_t start = atol(argv[i+1]);
            uint64_t uCount = atoi(argv[i+2]);
            
            dumpHexBytes(argv[argc-1], start, uCount);
        }
        if(!strcmp(argv[i], "-s")) /* TODO: This functionality is broken. */
        {
            int i, len = strlen(argv[i+1]);
            int isTrue = TRUE; /* TODO: Fix this. (currently segfaults)*/
            uint16_t charCount = 0; /* This need sanity checks.*/
            for(i = 0; i < len && isTrue; i++)
            {
                if(!isdigit(argv[i+1]))
                {
                    isTrue = FALSE;
                }
            }
            if(i > 0)
            {
                charCount = atoi(argv[i+1]);
                scanForStrings(argv[argc-1], charCount);
            }
            else
            {
                scanForStrings(argv[argc-1], 3);
            }
        }
        if(!strcmp(argv[i], "-strtab") || !strcmp(argv[i], "-st"))
        {
            char magic[6];
            enum BITS arch;
            
            if(mapFileToStruct(argv[argc-1], &fileHandle) == FAILED)
            {
                printf("Unable map %s into memory\n", argv[argc-1]);
                exit(-1);
            }
            strcpy(magic, fileHandle.p_data);
            /* TODO: Decide if ELF32 or ELF64 and print strtab. */
            // switch( (arch = isELF(&fileHandle.p_data)))
            // {
            //     case T_64:
            //         break;
            //     case T_32:
            //         break;
            //     default:
            //     case T_NO_ELF:
            //         break;
            // }
        }
    }
    

    unmapFileFromStruct(&fileHandle);
    return 0;
}

