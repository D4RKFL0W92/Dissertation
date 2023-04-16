#/bin/sh
elfinfo="../src/Modules/ELFinfo/elfinfo.c"
elfdynamic="../src/Modules/Dynamic/elfdynamic.c"
logging="../src/Logging/logging.c"
fileops="../src/FileOperations/fileOps.c"
cli="../src/CLI/cli.c"
memory="../src/Memory/turtle_memory.c"
io="../src/Modules/IO/io.c"

FLAGS=''
SSLLIB='/usr/bin/openssl -lssl -lcrypto'            # These may not always be in the same place
SSLINCLUDES='/usr/local/src/openssl-3.0.7/include'  # maybe we can locate these dynamically.

if [ $# -lt 1 ]; then
    FLAGS=''
elif [ $# -eq 1 ]; then
    if [ $1 == "-d" ]; then
        echo 'Building With Debug Logic Enabled.'
        FLAGS='-DDEBUG'
    elif [ $1 == '-u' ]; then
        echo 'Building With Unit Tests Enabled.'
        FLAGS='-DUNITTEST -DLOCALTESTFILES'
        gcc $FLAGS $elfinfo $elfdynamic $cli $logging \
        $fileops $memory $io \
        -L$SSLLIB -I$SSLINCLUDES -lm -ggdb -o Turtle-Scan
        echo "Running executable with unit tests..."
        ./Turtle-Scan -u
        exit
    fi
fi

gcc $FLAGS $elfinfo $elfdynamic $cli $logging \
$fileops $memory $io \
-L$SSLLIB -I$SSLINCLUDES -lm -ggdb -o Turtle-Scan

# Run the unit tests for the project on each build.
