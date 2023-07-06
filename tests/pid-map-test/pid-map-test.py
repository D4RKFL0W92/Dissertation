#!/usr/bin/env python3

# A simple test, only really checking if mapping an Elf executable
# handle from a PID given to the program as an option.

import re
import subprocess
from subprocess import PIPE

class PidMapTest:
    
    def __init__(self):
        self.objdumpStdout = ""
        self.objdumpStderr = ""
        self.turtleStdout  = ""
        self.turtleStderr  = ""

        self.testBin = "../executable_files/Turtle-Scan"

    def runPidOption(self):
        command = ["../../BUILD/Turtle-Scan", "-pid=3967", "-phdrs"]
        print("Begining PID map test....")

        process = subprocess.Popen(command, stdout=PIPE, stderr=PIPE)
        out, err = process.communicate()
        if process.returncode != 0 or err != None:
            print("TEST FAILED!.\n")
            print(out + err)
            return 1
        
        # We are not actually interested in the output for this test.
        print("PID Mapping Test Was Successful.")

if __name__ == "__main__":
    test = PidMapTest()
    test.runPidOption()