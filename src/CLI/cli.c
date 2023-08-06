/*
 * Copyright (c) [2023], Calum Dawson
 * All rights reserved.
 * This code is the exclusive property of Calum Dawson.
 * Any unauthorized use or reproduction without the explicit
 * permission of Calum Dawson is strictly prohibited.
 * Unauthorized copying of this file, via any medium, is
 * strictly prohibited.
 * Proprietary and confidential.
 * Written by Calum Dawson calumjamesdawson@gmail.com, [2023].
*/

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
  enum BITS arch = T_NO_ELF;
  MODE executionMode = UNKNOWN_MODE;
  char pidStr[5] = {0};
  BOOL usingPid = FALSE;
  uint16_t targetFileIndex = 0;
  uint16_t i = 1;
  uint16_t endOfProgArgs = argc;
  uint8_t err = ERR_NONE;

  if(argc < 2 || strcmp(argv[1], "-h") == 0)
  {
    printf(helpMenu);
    exit(-1);
  }

  else
  {
    /*
     * Check for options that specific ordering to their arguments.
    */

    /* Option: Print SHA1 of given file. */
    if(strcmp(argv[1], "-sha1") == 0)
    {
      if(printSHA1OfFile(argv[argc-1]) == ERR_UNKNOWN)
      {
        printf("Unable to calculate hash for %s.\n", argv[argc-1]);
        exit(-1);
      }
      exit(0);
    }

    /* Option: Dump hex bytes from given offset.*/
    else if(strcmp(argv[1], "-hd") == 0 &&
            executionMode == UNKNOWN_MODE)
    {
      // Only makes sense for UNKNOWN_MODE
      uint8_t err = ERR_NONE;
      uint64_t start = 0;
      uint64_t uCount = 0;

      err = stringToInteger(argv[2], &start);

      if(err != ERR_NONE)
      {
        printf("Byte Offset Provided In Incorrect Format.\n");
        exit(1);
      }

      err = stringToInteger(argv[3], &uCount);

      if(err != ERR_NONE)
      {
        printf("Count Provided In Incorrect Format.\n");
        exit(1);
      }
      if(uCount == 0)
      {
        printf("Count Must Be Greater Than Zero.\n");
      }
      
      err = dumpHexBytesFromFile(argv[argc-1], start, uCount);
      exit(err);
    }

    /*
     * Option: Lookup address of ELF symbol.
     * Usage: <Program> <-lookup> <symbol> <program-name>
    */
    else if(strcmp(argv[1], "-lookup") == 0)
    {
      uint64_t addr;

      if(argv[2] == NULL) // TODO: Could we make some check that it is a sensical name
      {
        printf("Please Provide A Symbol Name To Lookup.\n");
        exit(0);
      }

      if(argv[argc-1] == NULL)
      {
        printf("Please provide The Name Of An Executable File.\n");
      }

      err = mapFile_ElfHandle(argv[argc-1], &elfHandle);

      addr = lookupSymbolAddress(elfHandle, argv[2]);
      printf("<%s>\t0x%016lx\n", argv[2], addr);
      exit(0);
    }

    /* Option: Convert a hex passed as argument after switch value to decimal. */
    else if((strcmp(argv[1], "-h2d")) == 0)
    {
      uint64_t result = 0;
      uint8_t ret = 0;
      
      ret = hexToDecimal(argv[2], &result);
      printf("Result: %llu\n", result);
      exit(0);
    }

    // Determine which argument is the filepath/PID.
    for(int j = 1, found = FALSE; j < argc && found != TRUE; j++)
    {
      if(strncmp(argv[j], "-pid=", 5) == 0)
      {
        // TODO: Add some sanity checks
        found = TRUE; // We are using a PID instead of path
        usingPid = TRUE;
        executionMode = PID_MODE;

        if(strlen(argv[j]) <= 5)
        {
          printf("Please Provide A Valid Process ID, Usage: -pid=PID-VALUE\n");
          exit(ERR_INVALID_ARGUMENT);
        }
        strncpy(pidStr, &argv[j][5], 5);
        break;
      }
      else if(strncmp(argv[j], "-", 1) != 0) // First argument that doesn't start with -
      {
        executionMode = FILE_HANDLE_MODE;
        found = TRUE;
        targetFileIndex = j;
      }
      // Check if any bash special operators are present in the args
      else if(strncmp(argv[j], "|", 1) != 0 ||
              strncmp(argv[j], "&", 1) != 0 ||
              strncmp(argv[j], ">", 1) != 0 ||
              strncmp(argv[j], ">>", 2) != 0)
      {
        // TODO: It seems the program works in not processing these special commands but
        // they do not seem to work on the terminal.
        endOfProgArgs = j;
      }
    }
    
    if(usingPid == FALSE)
    {
      err = mapFile_ElfHandle(argv[targetFileIndex], &elfHandle);
    }
    else
    {
      mapELFToHandleFromPID(pidStr, &elfHandle, &arch);
    }


    /*
     * All functionality that relies on an elf/file handle
    */
    while(i <= endOfProgArgs)
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
        if(i != endOfProgArgs-1)
        {
          if(strcmp(argv[i + 1], "-v") == 0)
          {
            printSymbolTableData(elfHandle, ALL);
          }
        }
        else
        {
          printSymbolTableData(elfHandle, LOCAL);
        }
      }

      /* Option: Trace execution of an executable file. */
      else if(strcmp(argv[i], "-trace") == 0 &&
              executionMode == FILE_HANDLE_MODE)
      {
        char answer = "\0";

        printf("Running Trace On Untrusted Software Is A Security Risk\n" \
               "Be Sure To Only Run In A Sandboxed Environment.\n" \
               "Are You Sure You Would Like To Continue?  Y/N ");
        answer = getchar();
        if(answer == 'y' || answer == 'Y')
        {
          // TODO: Add some sanity checks
          launchTraceProgram(elfHandle, endOfProgArgs-targetFileIndex, &argv[targetFileIndex], envp);
        }
        else
        {
          exit(0);
        }
      }

      /* Option: Dump ASCII strings. */
      else if(strcmp(argv[i], "-s") == 0)
      {
        if(executionMode == PID_MODE)
        {
          ELF64_EXECUTABLE_HANDLE_T * tmpElf = (ELF64_EXECUTABLE_HANDLE_T *) elfHandle;
          scanFileForStrings(tmpElf->fileHandle.path, 3);
        }
        else
        {
          scanFileForStrings(argv[targetFileIndex], 3);
        }
      }

      /* TODO: Find a way to print out any unknown commands the user provides. */

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

    i++; // Increment the argv pointer.
    }

  }


  if(arch == T_64)
  {
    ELF64_EXECUTABLE_HANDLE_T * elf = (ELF64_EXECUTABLE_HANDLE_T *) elfHandle;
    free(elf->pTextSeg);
    free(elf->pDataSeg);
    free(elf->pBssSeg);
    free(elfHandle);
  }
  else if(arch == T_32)
  {
    ELF32_EXECUTABLE_HANDLE_T * elf = (ELF64_EXECUTABLE_HANDLE_T *) elfHandle;
    free(elf->pTextSeg);
    free(elf->pDataSeg);
    free(elf->pBssSeg);
    free(elfHandle);
  }
  else
  {
    free(elfHandle);
  }

  // Free All possible dynamic memory areas associated with a Handle.
  /* Check if fileHandle needs cleaning up. */
  if(fileHandle.p_data && fileHandle.st.st_size > 0)
  {
    unmapFileFromStruct(&fileHandle);
  }
  return 0;
}