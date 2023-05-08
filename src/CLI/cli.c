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

  if(argc < 2 || strcmp(argv[1], "-h") == 0)
  {
    printf(helpMenu);
    exit(-1);
  }

  do
  {
    /* Header info related options. */
    /*
     * Option:
     * Print verbose infomation found in the various ELF, section
     * and program headers of the file passed as last argument.
    */
    if(strcmp(argv[i], "-E") == 0)
    {
      if(mapFileToStruct(argv[argc-1], &fileHandle) == ERR_UNKNOWN)
      {
        printf("Unable map %s into memory\n", argv[argc-1]);
        exit(-1);
      }

      if(printElfInfoVerbose(&fileHandle) == ERR_UNKNOWN)
      {
        printf("Unable to get ELF info from %s\n", argv[argc-1]);
        exit(-1);
      }

    }

    /* Function related options. */
    /* Option: Handle dumping of imported function names. */
    else if(strcmp(argv[i], "-i") == 0 ||
       strcmp(argv[i], "-imports") == 0)
    {
      enum BITS arch;
      
      if(mapFileToStruct(argv[argc-1], &fileHandle) == ERR_UNKNOWN)
      {
        printf("Unable map %s into memory\n", argv[argc-1]);
        exit(-1);
      }
      printSymbolTableData(&fileHandle, IMPORTS);
    }

    /* Option: Local function dumping. */
    else if(strcmp(argv[i], "-f") == 0 ||
       strcmp(argv[i], "-functions") == 0)
    {
      enum BITS arch;
      
      if(mapFileToStruct(argv[argc-1], &fileHandle) == ERR_UNKNOWN)
      {
        printf("Unable map %s into memory\n", argv[argc-1]);
        exit(-1);
      }

      if(strcmp(argv[i], "-v") == 0)
      {
        printSymbolTableData(&fileHandle, ALL);
      }
      else
      {
        printSymbolTableData(&fileHandle, LOCAL);
      }
    }

    /*
     * Option:
     * Lookup address of ELF symbol.
    */
    else if(!strcmp(argv[i], "-lookup"))
    {
      uint64_t addr;
      if(mapFileToStruct(argv[argc-1], &fileHandle) == ERR_UNKNOWN)
      {
        printf("Unable map %s into memory.\n", argv[argc-1]);
        exit(-1);
      }

      if(argv[i + 1] == NULL) // TODO: Could we make some check that it is a sensical name
      {
        printf("Please Provide A Symbol Name To Lookup.\n");
        exit(0);
      }
      addr = lookupSymbolAddress(&fileHandle, argv[i + 1]);
      printf("<%s>\t0x%016lx", argv[i + 1], addr);
    }

    /* Option: Print SHA1 of given file. */
    else if(!strcmp(argv[i], "-sha1"))
    {
      if(printSHA1OfFile(argv[argc-1]) == ERR_UNKNOWN)
      {
        printf("Unable to calculate hash for %s.\n", argv[argc-1]);
        exit(-1);
      }
    }
    

    /* Option: Dump hex bytes from given offset.*/
    else if(!strcmp(argv[i], "-hd"))
    {
      uint8_t err = ERR_NONE;
      uint64_t start = 0;
      uint64_t uCount = 0;

      err = stringToInteger(argv[i+1], &start);

      if(err != ERR_NONE)
      {
        printf("Byte Offset Provided In Incorrect Format.\n");
        exit(1);
      }

      err = stringToInteger(argv[i+2], &uCount);

      if(err != ERR_NONE)
      {
        printf("Count Provided In Incorrect Format.\n");
        exit(1);
      }
      if(uCount == 0)
      {
        printf("Count Must Be Greater Than Zero.\n");
      }
      
      dumpHexBytesFromFile(argv[argc-1], start, uCount);
    }

    /* Option: Dump ASCII strings. */
    else if(!strcmp(argv[i], "-s")) /* TODO: Adapt this functionality to handle searching for strings of a given size. */
    {
      scanFileForStrings(argv[argc-1], 3);
    }

    /* Option: Convert a hex passed as argument after switch value to decimal. */
    else if(!(strcmp(argv[i], "-h2d")))
    {
      uint64_t result = 0;
      uint8_t ret = 0;
      
      ret = hexToDecimal(argv[i+1], &result);
      printf("Result: %llu\n", result);
      exit(0);
    }

    /* Debug_Option: Unit tests. */
    #ifdef UNITTEST
      if(!strcmp(argv[i], "-u"))
      {
        printf("Running Unit Tests...\n");
        fileOpsTestSuite();
        elfInfoTestSuite();
        // ioTestSuite();
        printf("Unit Tests Successful.\n");
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

