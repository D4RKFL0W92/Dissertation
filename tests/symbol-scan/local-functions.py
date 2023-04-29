#!/usr/bin/env python3
import sys
import os
import re
import subprocess
from subprocess import Popen, PIPE

class LocalFunctionExtractionTest:

    def __init__(self):
        self.objdumpStdout = ""
        self.objdumpStderr = ""
        self.turtleStdout  = ""
        self.turtleStderr  = ""

        self.objdumpSyms = {}
        self.turtleSyms  = {}

        self.testBin = "../executable_files/Turtle-Scan"

    def processObjdumpLocalSymbols(self, symbolList):
        localSymbols = {}
        
        if len(symbolList) < 1:
            return 1
        
        for symbol in symbolList:
            # print(symbol, "\n")
            if "@" not in symbol:
                addr       = re.findall("[0-9a-f]{16}", symbol)
                symbolName = re.findall("<.*>", symbol)
                print(symbolName, ": ", addr)
                # Add symbol + addr into a dictionary.

    def runObjdump(self):
        command = {"objdump", "-d", self.testBin}
        
        result = subprocess.Popen(command, stdout=PIPE, stderr=PIPE)
        self.objdumpStdout, self.objdumpStderr = result.communicate()
        if result.returncode != 0 or self.objdumpStdout == None:
            return 1
        
        allFunctionSymbols = re.findall("[0-9a-f]{16} <[a-zA-Z0-9]*@*[a-zA-Z0-9]*>", str(self.objdumpStdout))
        # print(allFunctionSymbols)
        if len(allFunctionSymbols) < 1:
            return 1
        
        self.processObjdumpLocalSymbols(allFunctionSymbols)


    def runTest(self):
        print("running objdump....")
        self.runObjdump()


if __name__ == "__main__":
    test = LocalFunctionExtractionTest()
    test.runTest()