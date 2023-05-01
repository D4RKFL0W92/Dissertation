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

        self.objdumpSyms     = {}
        self.objdumpSymNames = []
        self.turtleSyms  = {}

        self.testBin = "../executable_files/Turtle-Scan"
        self.testLog = "../test-logs/FunctionExtractionTest.log"
        self.log     = ""

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
                self.objdumpSyms.update({symbolName : addr})

        if len(self.objdumpSyms) < 1:
            return 1
        self.objdumpSymNames = list(self.objdumpSyms.keys())
        return 0

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
        self.log + "objdump Complete.\n"
        print("objdump Complete.")
        if ret != 0:
            return 1
        return 0

    # Function that runs Turtle-Scan with all the symbols extracted from the objdump
    # output, comparing the returned address of each to confirm successful parsing of symtab.
    def runLookupOfSymbols(self):
        for sym in self.objdumpSymNames:
            command = ["../../BUILD/Turtle-Scan", "-lookup", sym, self.testBin]
            print("Looking Up Address Of: ", sym)
            result = subprocess.Popen(command, stdout=PIPE, stderr=PIPE)
            time.sleep(1)
            out, err = result.communicate()
            if result.returncode != 0 or out == None:
                print("A Failure Has Occured In Lookup Symbols.")
                self.log + str(out)
                self.log + str(err)
                self.log + str("A Lookup Has Failed.\n")
                return 1
            
            addr = re.findall("[0-9a-f]{16}", str(out))
            print("Objdump Result: ", self.objdumpSyms[sym], "Turtle-Scan Result: ", addr)
            if addr != self.objdumpSyms[sym]:
                print("Addresses Don't Match")
            

    def runTest(self):
        print("running objdump....")
        
        objdumpRet = self.runObjdump()
        if objdumpRet != 0:
            self.log + str("objdump Failed:\n" + str(self.objdumpStdout) + str(self.objdumpStderr))
            self.writeLog()
            exit(1)
        
        print("Testing Lookup...")
        self.runLookupOfSymbols()
        # Write stderr + stdout to log file

    def writeLog(self):
        print(self.log)
        commonFunctionality.writeToFile(self.testLog, self.log)

    def printLogToConsole(self):
        print(self.log)


if __name__ == "__main__":
    test = LocalFunctionExtractionTest()
    test.runTest()
    # test.printLogToConsole()