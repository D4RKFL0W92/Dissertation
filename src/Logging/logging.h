/*
 * Copyright (c) [2023], Calum Dawson
 * All rights reserved.
 * This code is the exclusive property of Calum Dawson.
 * Any unauthorized use or reproduction without the explicit
 * permission of Calum Dawson is strictly prohibited.
 * Unauthorized copying of this file, via any medium, is
 * strictly prohibited.
 * Proprietary and confidential.
 * Written by Calum Dawson calumjamesdawson@gmail.com, [2023].
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