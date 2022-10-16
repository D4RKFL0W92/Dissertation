CC=gcc
BASEDIR=../
SRC=$BASEDIR/SRC
BUILD=$BASEDIR/BUILD

CFLAGS= -ggdb -m32

turtleScan :
    $(CC) elfinfo.o 

elfinfo.o : SRC/Modules/ELFinfo/elfinfo.c SRC/Modules/ELFinfo/elfinfo.h
    $(CC) $(CFLAGS) -c SRC/Modules/ELFinfo/elfinfo.c -o $@