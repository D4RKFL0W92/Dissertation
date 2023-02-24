#include <ctype.h>

#include "../Modules/ELFinfo/elfinfo.h"
#include "../Modules/Dynamic/elfdynamic.h"
#include "../Modules/IO/io.h"
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

        /* Dump the SHA1 hash of the file passed as the last argument. */
        if(!strcmp(argv[i], "-sha1"))
        {
            if(printSHA1OfFile(argv[argc-1]) == FAILED)
            {
                printf("Unable to calculate hash for %s.\n", argv[argc-1]);
                exit(-1);
            }
        }
        
        /* Print verbose infomation found in the various ELF, section
         * and program headers of the file passed as last argument.
        */
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
            /* TODO: Add some error checking here. */
            uint64_t start = atol(argv[i+1]);
            uint64_t uCount = atoi(argv[i+2]);
            
            dumpHexBytes(argv[argc-1], start, uCount);
        }

        if(!strcmp(argv[i], "-s")) /* TODO: Adapt this functionality to handle searching for strings of a given size. */
        {
            scanForStrings(argv[argc-1], 3);
        }

        /* Print all null terminated strings found in the string table. */
        if(!strcmp(argv[i], "-strtab") || !strcmp(argv[i], "-st"))
        {
            char magic[6];
            enum BITS arch;
            
            if(mapFileToStruct(argv[argc-1], &fileHandle) == FAILED)
            {
                printf("Unable map %s into memory\n", argv[argc-1]);
                exit(-1);
            }

            printElfStringTable(&fileHandle);
        }

        /* Print symbol table of the program given as last argument. */
        if(!strcmp(argv[i], "-symtab"))
        {
            enum BITS arch;
            
            if(mapFileToStruct(argv[argc-1], &fileHandle) == FAILED)
            {
                printf("Unable map %s into memory\n", argv[argc-1]);
                exit(-1);
            }

            printELFSymTable(&fileHandle);
        }

        /*
         * Lookup address of ELF symbol.
         * TODO: Finish implementation.
        */
        if(!strcmp(argv[i], "-lookup"))
        {
            uint64_t addr;
            if(mapFileToStruct(argv[argc-1], &fileHandle) == FAILED)
            {
                printf("Unable map %s into memory\n", argv[argc-1]);
                exit(-1);
            }

            addr = lookupSymbolAddress(&fileHandle, "main");
        }

        /* Convert a hex passed as argument after switch value to decimal. */
        if(!(strcmp(argv[i], "-h2d")))
        {
            uint64_t result = hexToDecimal(argv[i+1]);
            printf("Result: %llu\n", result);
            exit(0);
        }

        /* Unit tests. */
        #ifdef UNITTEST
            if(!strcmp(argv[i], "-u"))
            {
                fileOpsTestSuite();
                elfInfoTestSuite();
                ioTestSuite();
            }
        #endif

    }while(i++ < argc-1);
    
    /* Check if fileHandle needs cleaning up. */
    if(fileHandle.p_data && fileHandle.st.st_size > 0)
    {
        unmapFileFromStruct(&fileHandle);
    }
    return 0;
}

