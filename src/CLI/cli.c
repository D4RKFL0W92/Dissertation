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
    int i = 1;

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

    do
    {
        /* Unit tests. */
        #ifdef UNITTEST
        if(!strcmp(argv[i], "-u"))
        {
            fileOpsTestSuite();
            elfInfoTestSuite();
        }
        #endif

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

        }

        if(!strcmp(argv[i], "-hd"))
        {
            uint64_t start = atol(argv[i+1]);
            uint64_t uCount = atoi(argv[i+2]);
            
            dumpHexBytes(argv[argc-1], start, uCount);
        }

        if(!strcmp(argv[i], "-s")) /* TODO: This functionality is broken. */
        {
            scanForStrings(argv[argc-1], 3);
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

            strncpy(magic, fileHandle.p_data, 6);
            arch = isELF(magic);

            /* TODO: Finish implementing for 32 bit. */
            switch(arch)
            {
                case T_64:
                    ELF64_EXECUTABLE_HANDLE_T elfHandle64;
                    mapELF64ToHandleFromFileHandle(&fileHandle, &elfHandle64);
                    printELF64StrTable(&elfHandle64);
                    break;
                case T_32:
                    ELF32_EXECUTABLE_HANDLE_T elfHandle32;
                    mapELF32ToHandleFromFileHandle(&fileHandle, &elfHandle32);
                    printELF32StrTable(&elfHandle32);
                    break;
                default:
                case T_NO_ELF:
                    break;
            }
        }

        if(!strcmp(argv[i], "-symtab"))
        {
            char magic[6];
            enum BITS arch;
            
            if(mapFileToStruct(argv[argc-1], &fileHandle) == FAILED)
            {
                printf("Unable map %s into memory\n", argv[argc-1]);
                exit(-1);
            }

            strncpy(magic, fileHandle.p_data, 6);
            arch = isELF(magic);

            /* TODO: Finish implementing for 32 bit. */
            switch(arch)
            {
                case T_64:
                    ELF64_EXECUTABLE_HANDLE_T elfHandle64;
                    if( (mapELF64ToHandleFromFileHandle(&fileHandle, &elfHandle64)) == FAILED)
                    {
                        exit(FAILED);
                    }
                    printELF64SymTable(&elfHandle64);
                    break;
                case T_32:
                    ELF32_EXECUTABLE_HANDLE_T elfHandle32;
                    mapELF32ToHandleFromFileHandle(&fileHandle, &elfHandle32);
                    printELF32SymTable(&elfHandle32);
                    break;
                default:
                case T_NO_ELF:
                    break;
            }
        }

    }while(i++ < argc-1);
    

    if(fileHandle.p_data && fileHandle.st.st_size > 0)
    {
        unmapFileFromStruct(&fileHandle);
    }
    return 0;
}

