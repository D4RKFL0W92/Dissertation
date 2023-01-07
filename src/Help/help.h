
const char helpMenu[] = "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%-Turtle-Scan-%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n" \
                        "--------------------------------Help Menu--------------------------------\n\n\n" \
                        "Usage: < Turtle-Scan > < -Opt1 -Opt2, ... > < Executable >\n" \
                        "-------------------------------------------------------------------------\n\n\n" \
                        "\t-sha1\n\t"         "Prints the sha1 hash of the file given as a final parameter.\n\n" \
                        "\t-E\n\t"            "Prints useful information about an ELF executable, (given as final argument).\n\n" \
                        "\t-strtab | -st\n\t" "Dumps the string table of the given binary (final parameter).\n\n" \
                        "\t-s\n\t"            "Scans the given binary for ASCII strings, will work on all files, not just binaries.\n\n" \
                        "\t-hd\n\t"           "Usage: -hd <offset> <byte count>. Hex dump a specified number of bytes from given offset.\n\n" \
                        
                        
                        
                        "\t-u\n\t"            "Runs all unit tests for the project.\n\n";