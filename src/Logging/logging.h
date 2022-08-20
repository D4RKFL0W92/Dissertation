#ifndef _LOGGING_
#define _LOGGING_

#include <stdio.h>

#define DEBUG

#define LOG_FILE "/home/calum/Dissertation_Project/Logs/elfinfo_logs"

int logEvent(const char* filepath, const char* func_name, const char* cause);

#endif