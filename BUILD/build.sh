#/bin/bash
elfinfo="../src/Modules/ELFinfo/elfinfo.c"
elfdynamic="../src/Modules/Dynamic/elfdynamic.c"
logging="../src/Logging/logging.c"
fileops="../src/FileOperations/fileOps.c"
cli="../src/CLI/cli.c"
memory="../src/Memory/turtle_memory.c"
vector="../src/Memory/tvector.c"
io="../src/Modules/IO/io.c"

FLAGS='-DDEBUG -DUNITTEST'
SSLLIB='/usr/bin/openssl -lssl -lcrypto'            # These may not always be in the same place
SSLINCLUDES='/usr/local/src/openssl-3.0.7/include'  # maybe we can locate these dynamically.

if [ $# -eq 1 ]; then
  echo '1 Arg Provided'
  if [ $1 = '-d' ]; then
    echo 'Building Without Debug Symbols'
    FLAGS='-DUNITTEST'
  elif [ $1 = '-u' ]; then
    echo 'Building Without Unit Tests'
    FLAGS='-DDEBUG'
  fi
elif [ $# -eq 2 ]; then
  echo '2 Args Provided'
  if [ $1 = '-d' -a $2 = '-u' ]; then # No extra flags (release build)
    echo 'Building Withoud Unit Tests Or Debug Symbols'
    FLAGS=''
  elif [ $1 = '-u' -a $2 = '-d' ]; then # No extra flags (release build)
    echo 'Building Withoud Unit Tests Or Debug Symbols'
    FLAGS=''
  fi
fi

gcc $FLAGS $elfinfo $elfdynamic $cli $logging \
$fileops $memory $vector $io \
-L$SSLLIB -I$SSLINCLUDES -lm -ggdb -o Turtle-Scan

# Run the unit tests for the project on each build.
