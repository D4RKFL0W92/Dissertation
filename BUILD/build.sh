#/bin/sh
elfinfo="../src/Modules/ELFinfo/elfinfo.c"
elfdynamic="../src/Modules/Dynamic/elfdynamic.c"
logging="../src/Logging/logging.c"
fileops="../src/FileOperations/fileOps.c"
cli="../src/CLI/cli.c"
memory="../src/Memory/turtle_memory.c"



gcc $elfinfo $elfdynamic $cli $logging \
$fileops $memory \
-Lopenssl/openssl-0.9.8k/ -lssl -lcrypto -Iopenssl/openssl-0.9.8k/include -ggdb -o Turtle-Scan

# Run the unit tests for the project on each build.
echo "Running executable with unit tests..."
./Turtle-Scan -u