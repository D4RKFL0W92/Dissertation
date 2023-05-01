#!/usr/bin/env python3
import sys
import time
import re
import subprocess
from subprocess import PIPE
sys.path.append("../")
import commonFunctionality

class LocalFunctionExtractionTest:

    def __init__(self):
        self.objdumpStdout = ""
        self.objdumpStderr = ""
        self.turtleStdout  = ""
        self.turtleStderr  = ""

        self.objdumpLocalSyms       = {}
        self.objdumpImportSyms      = {}
        self.objdumpLocalSymNames   = []
        self.objdumpImportSymNames  = []
        
        self.turtleLocalSyms      = {}
        self.turtleImportSyms     = {}
        self.turtleSymNames       = []

        self.testBin = "../executable_files/Turtle-Scan"

    def processObjdumpLocalSymbols(self, symbolList):
        if len(symbolList) < 1:
            return 1
        
        for symbol in symbolList:
            if "@" not in symbol: # exclude imports
                addr       = re.findall("[0-9a-f]{16}", symbol)[0]
                symbolName = re.findall("<.*>", symbol)[0]
                symbolName = symbolName.translate({ord('<'): None})
                symbolName = symbolName.translate({ord('>'): None})
                symbolName = symbolName.strip()
                print(symbolName)
                # Add symbol + addr into a dictionary.
                self.objdumpLocalSyms.update({symbolName : str(addr)})
            else:
                addr       = re.findall("[0-9a-f]{16}", symbol)[0]
                symbolName = re.findall("<.*>", symbol)[0]
                symbolName = symbolName.translate({ord('<'): None})
                symbolName = symbolName.translate({ord('>'): None})
                symbolName = symbolName.strip()
                print(symbolName)
                # Add symbol + addr into a dictionary.
                self.objdumpImportSyms.update({symbolName : str(addr)})

        # Some Binaries will have only local or imported function.
        if len(self.objdumpLocalSyms) < 1 and len(self.objdumpImportSyms) < 1:
            return 1
        self.objdumpLocalSymNames  = list(self.objdumpLocalSyms.keys())
        self.objdumpImportSymNames = list(self.objdumpImportSyms.keys())
        return 0
    
    # Function runs objdump and extracs all function symbol names and addresses.
    def runObjdump(self):
        command = ["objdump", "-d", self.testBin]
        
        result = subprocess.Popen(command, stdout=PIPE, stderr=PIPE)
        time.sleep(1) # This gives objdump time to complete. (subprocess.call() just hangs)
        self.objdumpStdout, self.objdumpStderr = result.communicate()
        if result.returncode != 0 or self.objdumpStdout == None:
            print("A failure has occured whilst running objdump.")
            return 1
        
        allFunctionSymbols = re.findall("[0-9a-f]{16} <[a-zA-Z0-9]*@*[a-zA-Z0-9]*>", str(self.objdumpStdout))
        if len(allFunctionSymbols) < 1:
            return 1
        
        ret = self.processObjdumpLocalSymbols(allFunctionSymbols)
        print("\nobjdump Complete.\n")
        if ret != 0:
            return 1
        return 0

    # Function that runs Turtle-Scan with all the symbols extracted from the objdump
    # output, comparing the returned address of each to confirm successful parsing of symtab.
    def runLookupOfSymbols(self):
        for sym in self.objdumpLocalSymNames:
            objdumpAddr = str(self.objdumpLocalSyms.get(sym))
            command = ["../../BUILD/Turtle-Scan", "-lookup", sym, self.testBin]
            print("Looking Up Address Of: ", sym)
            result = subprocess.Popen(command, stdout=PIPE, stderr=PIPE)
            time.sleep(1)
            out, err = result.communicate()
            if result.returncode != 0 or out == None:
                print("A Failure Has Occured In Lookup Symbols.\n")
                print(out + err)
                return 1
            
            addr = re.findall("[0-9a-f]{16}", str(out))[0]
            if addr == None:
                print("Unable To Extract Address In Lookup Symbols\n")
                return 1
            print("Objdump Result: ", objdumpAddr, "Turtle-Scan Result: ", addr + "\n")
            if addr != objdumpAddr:
                print("Addresses Don't Match")
                return 1
            
        return 0
            

    def runTest(self):
        print("running objdump....\n")
        
        objdumpRet = self.runObjdump()
        if objdumpRet != 0:
            print("objdump Failed:\n" + str(self.objdumpStdout) + str(self.objdumpStderr))
            exit(1)
        else:
            print("Testing Lookup...\n")
            turtleRet = self.runLookupOfSymbols()
            if turtleRet != 0:
                print("Turtle-Scan Lookup Test Failed.")
            print("Lookup Test Successful.\n")


if __name__ == "__main__":
    test = LocalFunctionExtractionTest()
    test.runTest()
    # test.printLogToConsole()