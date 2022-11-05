#/bin/sh
elfinfo="../src/Modules/ELFinfo/elfinfo.c"
elfdynamic="../src/Modules/Dynamic/elfdynamic.c"
logging="../src/Logging/logging.c"
fileops="../src/FileOperations/fileOps.c"
cli="../src/CLI/cli.c"
file_ops="../src/FileOperations/fileOps.c"



gcc $elfinfo $elfdynamic $cli $logging \
$file_ops -Lopenssl/openssl-0.9.8k/ -lssl -lcrypto -Iopenssl/openssl-0.9.8k/include -ggdb -o turtle_scan