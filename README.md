Turtle-Scan

Description:
  Turtle-Scan is a binary forensic framework. The intention of this project was to develop and utilise a library designed for extracting
  useful information from ELF executable files. Turtle-Scan is the utilisation of this library.
  Included in the codebase is a python build script that will build the tool for a user.

Features:
  * Capable of dumping ELFHeader, Phdrs and Shdrs of an ELF binary image or running process.
  * Capable of tracing program execution through different syscalls dumping relevant data (similar to strace).
  * Can dump memory segments of a running process given that processes PID.
  * Scan and dump any file for ASCII strings.
  * Hash a executable file in either SHA1 & SHA256.
  * Read and display a ASCII & hexidecimal representation of bytes read from a file or executing process.

Dependencies:
  OpenSSL