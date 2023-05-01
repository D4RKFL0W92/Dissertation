#!/usr/bin/env python3

def writeToFile(file, out):
    try:
        with open(file, "a") as file:
            file.write(str(out) + "\n")
    except IOError as e:
        print("Exception: ", e)

# TODO: Write function to handle executing a subprocess with timeout.