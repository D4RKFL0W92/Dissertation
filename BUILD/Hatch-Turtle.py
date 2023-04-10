#!/usr/bin/env python3
import sys
from subprocess import Popen, PIPE

class Hatch:

    def __init__(self):
        self.elfInfo = "../src/Modules/ELFinfo/elfinfo.c"
        self.elfdynamic = "../src/Modules/Dynamic/elfdynamic.c"
        self.logging = "../src/Logging/logging.c"
        self.fileops = "../src/FileOperations/fileOps.c"
        self.cli = "../src/CLI/cli.c"
        self.memory = "../src/Memory/turtle_memory.c"
        self.io = "../src/Modules/IO/io.c"

        self.FLAGS = ""
        self.SSLLIB = "/usr/bin/openssl"            # These may not always be in the same place
        self.SSLINCLUDES = "/usr/local/src/openssl-3.0.7/include"  # maybe we can locate these dynamically.
        
        self.buildParameters = [self.elfInfo, self.elfdynamic, self.logging, self.fileops, self.cli, self.memory, self.io, "-L", self.SSLLIB, "-lssl", "-lcrypto", "-I", self.SSLINCLUDES, "-lm"]

        self.process = None
        self.stdout = ""
        self.stderr = ""

    def setFlags(self, flags):
        self.FLAGS = flags
        self.buildParameters.insert(0, self.FLAGS)

    def hatchTurtle(self):
        self.buildParameters.insert(0, "gcc")
        self.buildParameters.append("-o")
        self.buildParameters.append("Turtle-Scan")
        process = Popen(self.buildParameters, stdout=PIPE, stderr=PIPE)
        self.stdout, self.stderr = process.communicate()

        print(self.stdout, self.stderr)

if __name__ == "__main__":
    turtle = Hatch()

    if len(sys.argv) < 2:
        self.FLAGS=""
    elif len(sys.argv) == 2:
        if "-d" in sys.argv[1]:
            print("Building With Debug Logic Enabled.")
            turtle.setFlags("-DDEBUG")

        elif "-u" in sys.argv[1]:
            print("Building With Unit Tests Enabled.")
            turtle.setFlags("-DUNITTEST -DLOCALTESTFILES")

    turtle.hatchTurtle()
