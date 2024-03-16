#!/usr/bin/env python3

from os import listdir
from os.path import isfile, join
import os
import re

shasMatch = False

fileDirectory = "../files/"
logFile = "./sha1-log.txt"

files = [f for f in listdir(fileDirectory) if isfile(join(fileDirectory, f))]
os.system("rm ./sha1-log.txt")

for f in files:
	path = fileDirectory + str(f)
	os.system("../../BUILD/Turtle-Scan -sha1 " + path + " >> " + logFile)
	realSha = os.system("sha1sum " + path + " >> " + logFile)

# Read the file line by line, (for some reason sha1sum also outputs the filename,
# this will have to be stripped before comparison).
with open(logFile) as file:
	hasNext = True
	trueSha = ""
	mySha = ""
	while hasNext:
		line = file.readline()
		tSha1 = re.findall("\\b[0-9a-fA-F]{40}\\b", str(line))
		if not line:
			hasNext = False
			break
		else:
			mySha = line.split()[0]

		# Grab the true sha for comparison
		line = file.readline()
		sumSha = re.findall("\\b[0-9a-fA-F]{40}\\b", str(line))
		if not line:
			hasNext = False
			break
		else:
			trueSha = line.split()[0]

		#compare the two hashes
		if tSha1 != sumSha:
			shasMatch = False
			print("Hashes don't match!\n" + "Turtle Sha: " + mySha + "\nSha Sum: " + trueSha)
		else:
			shasMatch = True
			

if shasMatch:
	print("All SHA Values Match")