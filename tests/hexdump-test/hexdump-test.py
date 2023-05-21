import re
import subprocess
from subprocess import PIPE

# A simple functional test to test the hexdumping functionality
# of the project. The test will just dump bytes from an offset
# then compare said bytes with bytes read from the same offset/file
# read using Python read function.

class HexdumpTest:

    def __init__(self):

        self.pythonReadBytes = []
        self.turtleReadBytes = []

        self.testBin = "../executable_files/Turtle-Scan"


    def turtleDumpBytes(self):
        command = ["../../BUILD/Turtle-Scan", "-hd", "0", "100", self.testBin]
        print("Dumping 100 bytes from start of file: " + self.testBin)

        process = subprocess.Popen(command, stdout=PIPE, stderr=PIPE)
        out, err = process.communicate()
        if process.returncode != 0 or out == None:
            print("Unable To Perform Hexdump On " + self.testBin)
            print(out + err)
            return 1
        
        tmpTurtleReadBytes = re.findall("\\b[0-9a-f]{2}\\b", str(out))

        # Strip off the offset bytes from Turtle-Scan output
        for i in range(10, len(tmpTurtleReadBytes)):
            self.turtleReadBytes.append(tmpTurtleReadBytes[i])
        print("Turtle Read Bytes:")
        print(self.turtleReadBytes)

    def pythonReadBytesFromFile(self):
        with open(self.testBin, "rb") as f:
            for i in range(0, 100):
                b = f.read(1)
                self.pythonReadBytes.append(b.hex())
        print("Python Read Bytes:")
        print((self.pythonReadBytes))

    def runTest(self):
        print("Running Hexdump Functional Test.")

        self.turtleDumpBytes()
        self.pythonReadBytesFromFile()

        # Perform the comparison of bytes
        for i in range(0, 100):
            if self.turtleReadBytes[i] != self.pythonReadBytes[i]:
                print("Test Failed.")
                exit(1)
        print("Test Passed.")


if __name__ == "__main__":
    test = HexdumpTest()
    test.runTest()