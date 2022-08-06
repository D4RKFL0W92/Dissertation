#ifndef _LOGGING_
#define _LOGGING_

#include <stdio.h>

int logEvent(char* filepath, const char* func_name, const char* cause);
int logEvent(char* filepath, const char* func_name, const char* cause)
{
    FILE* file;

    if( (file = fopen(filepath, "a+")) == NULL)
    {
        perror("Unable to log error");
        return -1;
    }

    if(fprintf(file, "%s failed while calling %s", func_name, cause) < 0)
    {
        perror("Unable to write log to file.");
        return -1;
    }

    return 1;
}

#endif