#include <ctype.h>

#include "../Modules/ELFinfo/elfinfo.h"
#include "../Modules/Dynamic/elfdynamic.h"
#include "../Modules/IO/io.h"
#include "../FileOperations/fileOps.h"
#include "../Memory/turtle_memory.h"
#include "../Memory/tvector.h"
#include "../Help/help.h"

#define TEST32 "/home/calum/Test_Files/while32"
#define TEST64 "/home/calum/Test_Files/while64"

#define TEST32_2 "/home/calum/Test_Bins/while2_32"
#define TEST64_2 "/home/calum/Test_Bins/while2_64"

#define TEST_STRINGS "/home/calum/Test_Files/strings"

int main(int argc, char *argv[], char *envp[])
{
  FILE_HANDLE_T fileHandle = {0};
  ELF_EXECUTABLE_T * elfHandle = NULL;
  enum BITS arch;
  char pidStr[5] = {0};
  int i = 1;
  BOOL usingPid = FALSE;
  int targetFileIndex = 0;
  uint8_t err = ERR_NONE;

  if(argc < 2 || strcmp(argv[1], "-h") == 0)
  {
    printf(helpMenu);
    exit(-1);
  }

  if(argc >= 3)
  {
    for(int j = 1, found = FALSE; j < argc && found != TRUE; j++)
    {
      if(strncmp(argv[j], "-pid=", 5) == 0)
      {
        // TODO: Add some sanity checks
        found = TRUE; // We are using a PID instead of path
        usingPid = TRUE;

        if(strlen(argv[j]) <= 5)
        {
          printf("Please Provide A Valid Process ID, Usage: -pid=1234\n");
          exit(ERR_INVALID_ARGUMENT);
        }
        strncpy(pidStr, &argv[j][5], 5);
      }
      else if(strncmp(argv[j], "-", 1) != 0) // First argument that doesn't start with -
      {
        found = TRUE;
        targetFileIndex = j;
      }
    }
    
    // We only need to write code to determine the ELF architecture once.
    if(usingPid == FALSE)
    {
      if(mapFileToStruct(argv[targetFileIndex], &fileHandle) == ERR_UNKNOWN)
      {
        printf("Unable map %s into memory\n", argv[targetFileIndex]);
        exit(-1);
      }

      arch = isELF(fileHandle.p_data); // Not a failure if not an ELF, we may be scanning strings etc.
      if(arch == T_64)
      {
        mapELF64ToHandleFromFileHandle(&fileHandle, (ELF64_EXECUTABLE_HANDLE_T *) &elfHandle);
      }
      else if(arch == T_32)
      {
        mapELF32ToHandleFromFileHandle(&fileHandle, (ELF32_EXECUTABLE_HANDLE_T *) &elfHandle);
      }

    }
    else
    {
      mapELFToHandleFromPID(pidStr, elfHandle);
    }
  }

  do
  {
    /* Header info related options. */
    /*
     * Option:
     * Print verbose infomation found in the various ELF, section
     * and program headers of the file passed as last argument.
    */
    if(strcmp(argv[i], "-E") == 0 && usingPid == FALSE) // This option relies on a path rather than a PID. (Can we change this).
    {
      if(mapFileToStruct(argv[targetFileIndex], &fileHandle) == ERR_UNKNOWN)
      {
        printf("Unable map %s into memory\n", argv[targetFileIndex]);
        exit(-1);
      }

      if(printElfInfoVerbose(&fileHandle) == ERR_UNKNOWN)
      {
        printf("Unable to get ELF info from %s\n", argv[targetFileIndex]);
        exit(-1);
      }

    }
    /* Option: Prints the program header info contained in the binary. */
    else if(strcmp(argv[i], "-phdrs") == 0)
    {
      err = printELFProgramHeaders(elfHandle);
    }
    /* Option: Prints the section header info contained in the binary. */
    else if(strcmp(argv[i], "-shdrs") == 0)
    {
      err = printELFSectionHeaders(elfHandle);
    }

    /* Function related options. */
    /* Option: Handle dumping of imported function names. */
    else if(strcmp(argv[i], "-i") == 0 ||
            strcmp(argv[i], "-imports") == 0)
    {
      printSymbolTableData(elfHandle, IMPORTS);
    }

    /* Option: Local function dumping. */
    else if(strcmp(argv[i], "-f") == 0 ||
            strcmp(argv[i], "-functions") == 0)
    {

      if(strcmp(argv[i], "-v") == 0)
      {
        printSymbolTableData(elfHandle, ALL);
      }
      else
      {
        printSymbolTableData(elfHandle, LOCAL);
      }
    }

    /*
     * Option:
     * Lookup address of ELF symbol.
    */
    else if(!strcmp(argv[i], "-lookup"))
    {
      uint64_t addr;

      if(argv[i + 1] == NULL) // TODO: Could we make some check that it is a sensical name
      {
        printf("Please Provide A Symbol Name To Lookup.\n");
        exit(0);
      }
      addr = lookupSymbolAddress(elfHandle, argv[i + 1]);
      printf("<%s>\t0x%016lx", argv[i + 1], addr);
    }

    /* Option: Trace execution of an executable file. */
    else if(strcmp(argv[i], "-trace") == 0)
    {
      // TODO: Add some sanity checks
      launchTraceProgram(elfHandle, argc-targetFileIndex, &argv[targetFileIndex], envp);

    }

    /* Option: Print SHA1 of given file. */
    else if(!strcmp(argv[i], "-sha1"))
    {
      if(printSHA1OfFile(argv[targetFileIndex]) == ERR_UNKNOWN)
      {
        printf("Unable to calculate hash for %s.\n", argv[targetFileIndex]);
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
      
      dumpHexBytesFromFile(argv[targetFileIndex], start, uCount);
    }

    /* Option: Dump ASCII strings. */
    else if(!strcmp(argv[i], "-s")) /* TODO: Adapt this functionality to handle searching for strings of a given size. */
    {
      scanFileForStrings(argv[targetFileIndex], 3);
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
      if(strcmp(argv[i], "-u") == 0 ||
         strcmp(argv[i], "-unittest") == 0)
      {
        printf("Running Unit Tests...\n");
        fileOpsTestSuite();
        elfInfoTestSuite();
        elfDynamicTestSuite();
        ioTestSuite();
        TVectorTestSuite();
        printf("Unit Tests Successful.\n");
      }
    #endif

  }while(i++ < targetFileIndex);
  
  free(elfHandle);
  /* Check if fileHandle needs cleaning up. */
  if(fileHandle.p_data && fileHandle.st.st_size > 0)
  {
    unmapFileFromStruct(&fileHandle);
  }
  return 0;
}

