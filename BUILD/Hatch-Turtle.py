#!/usr/bin/env python3
import sys
from subprocess import Popen, PIPE
import os

class Hatch:

    def __init__(self):
        self.elfInfo = "../src/Modules/ELFinfo/elfinfo.c"
        self.elfdynamic = "../src/Modules/Dynamic/elfdynamic.c"
        self.logging = "../src/Logging/logging.c"
        self.fileops = "../src/FileOperations/fileOps.c"
        self.cli = "../src/CLI/cli.c"
        self.memory = "../src/Memory/turtle_memory.c"
        self.vector = "../src/Memory/tvector.c"
        self.io = "../src/Modules/IO/io.c"

        self.FLAGS = ""
        self.SSLLIB = "/usr/bin/openssl"            # These may not always be in the same place
        self.SSLINCLUDES = "/usr/local/src/openssl-3.0.7/include"  # maybe we can locate these dynamically.
        
        self.buildParameters = [self.elfInfo, self.elfdynamic, self.logging, self.fileops, self.cli, self.memory, self.vector, self.io, "-L", self.SSLLIB, "-lssl", "-lcrypto", "-I", self.SSLINCLUDES, "-lm"]

        self.process = None
        self.stdout = ""
        self.stderr = ""

        # Definitions of Path names to different test scripts:
        # Any new tests should be added here to include them in the automated CI.
        self.tests = [
            "../tests/symbol-scan/symbol-scan.py",
            "../tests/hexdump-test/hexdump-test.py"
        ]

    def setFlags(self, flags):
        self.FLAGS = flags
        self.buildParameters.insert(0, self.FLAGS)

    def runTest(self, testPath):
        startDir = os.getcwd()
        dirs = testPath.split('/')
        sep = '/'
        path = []
        for j in range(0, len(dirs)-1):
            path.append(dirs[j])

        dir = sep.join(path)
        os.chdir(dir)

        buildParameters = ["python3", dirs[len(dirs)-1]]
        print("Running Test: " + str(dirs[len(dirs)-1]))
        process = Popen(buildParameters, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            print("TEST FAILED: " + str(dirs[len(dirs)-1]))
        else:
            print("TEST SUCCEEDED: " + str(dirs[len(dirs)-1]))

        # Write log to file in the test directory.
        logFile = dirs[len(dirs)-1].split('.')[0]
        self.writeFormattedLog(logFile, stdout, stderr)
        
        os.chdir(startDir)

    def writeFormattedLog(self, logFile, out, err):
        out = str(out)
        outLines = out.split("\\n")
        err = str(err)
        errLines = out.split("\\n")
        with open(logFile + ".log", 'w') as f:
            for line in outLines:
                f.write(line + '\n') 
            for line in errLines:
                f.write(line + '\n') 

    def hatchTurtle(self, runFunctionalTests):
        os.system("rm ./Turtle-Scan")
        
        self.buildParameters.insert(0, "gcc")
        self.buildParameters.append("-o")
        self.buildParameters.append("Turtle-Scan")

        process = Popen(self.buildParameters, stdout=PIPE, stderr=PIPE)
        self.stdout, self.stderr = process.communicate()

        if process.returncode != 0:
            print(self.stdout, self.stderr)
            print("|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||")
            print("------------------------------ BUILD FAILED -----------------------------------")
            print("|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||")
            exit(1)

        else:
            # TODO: Process stdout/stderr.
            print(self.stdout, self.stderr)

            # Optionally run functional tests
            if runFunctionalTests == True:
                for i in range(0, len(self.tests)):
                    self.runTest(self.tests[i])

if __name__ == "__main__":
    turtle = Hatch()

    if len(sys.argv) < 2:
        turtle.setFlags("")
        turtle.hatchTurtle(True)
        exit(0)
    elif len(sys.argv) >= 2:
        if "-d" in sys.argv:
            print("Building With Debug Logic Enabled.")
            turtle.setFlags("-DDEBUG")
            turtle.setFlags("-ggdb")

        elif "-u" in sys.argv:
            print("Building With Unit Tests Enabled.")
            turtle.setFlags("-DDEBUG")
            turtle.setFlags("-ggdb")
            turtle.setFlags("-DUNITTEST -DLOCALTESTFILES")

    if "-notests" in sys.argv:
        turtle.hatchTurtle(False)
    else:
        turtle.hatchTurtle(True)