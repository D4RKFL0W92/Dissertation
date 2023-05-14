
const char helpMenu[] = "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%-Turtle-Scan-%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n" \
                        "--------------------------------Help Menu--------------------------------\n\n\n" \
                        "Usage: < Turtle-Scan > < -Opt1 -Opt2, ... > < Executable >\n" \
                        "-------------------------------------------------------------------------\n\n\n" \

                        "Header Related Options:\n" \
                        "-------------------------------------------------------------------------\n\n\n" \
                        "\t-E\n\t"            "Prints useful information about an ELF executable, (given as final argument).\n\n" \
                        "\t-phdrs\n\t"        "Prints all program header data in the ELF executable, (given as final argument).\n\n" \
                        "\t-shdrs\n\t"        "Prints all section header data in the ELF executable, (given as final argument).\n\n" \

                        "Function Related Options:\n" \
                        "-------------------------------------------------------------------------\n\n\n" \
                        "\t-i\n\t"            "Usage: -i Print imported functions used by an ELF executable (final parameter).\n\n" \
                        "\t-f\n\t"            "Usage: -f Print local functions refereced by an ELF executable (final parameter).\n\n" \
                        "\t-lookup\n\t"       "Usage: -lookup <symbol_name> Print the address of the provided symbol if" \
                                                       "found within the provided ELF binary(final parameter).\n\n" \
                        
                        "Data Dumping Related Options:\n" \
                        "-------------------------------------------------------------------------\n\n\n" \
                        "\t-sha1\n\t"         "Usage: -sha1 <File> Prints the sha1 hash of the file given as a final parameter.\n\n" \
                        "\t-s\n\t"            "Usage: -s <File> Scans the given binary for ASCII strings," \
                                                        "will work on all files, not just binaries.\n\n" \
                        "\t-hd\n\t"           "Usage: -hd <offset> <byte count>. Hex dump a specified number of bytes from given offset.\n\n" \
                        
                        "Data Representation Related Options:\n" \
                        "-------------------------------------------------------------------------\n\n\n" \
                        "\t-h2d\n\t"         "Usage: -h2d <hex value> Converts a hex value to decimal.\n\n" \
                        
                        "\t-u\n\t"            "Runs all unit tests for the project.\n\n";