/*
 * Copywrite: 2023 Calum Dawson calumjamesdawson@gmail.com
*/

#ifndef _LOGGING_
#define _LOGGING_

#include <stdio.h>
#include <errno.h>
#include "../Types/turtle_types.h"

extern errno;

#define LOG_FILE "/home/calum/Dissertation_Project/Logs/elfinfo_logs"

int logEvent(const char* filepath, const char* func_name, const char* cause);
int clearLogFile(const char* filepath);

#endif