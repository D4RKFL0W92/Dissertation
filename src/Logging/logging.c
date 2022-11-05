#include "./logging.h"

int logEvent(const char* filepath, const char* func_name, const char* cause)
{
    FILE* file;

    if( (file = fopen(filepath, "a+")) == NULL)
    {
        #ifdef DEBUG
        perror("Unable to log error");
        #endif
        return FAILED;
    }

    if(fprintf(file, "%s failed while calling %s\n", func_name, cause) < 0)
    {
        #ifdef DEBUG
        perror("Unable to write log to file.");
        #endif
        return FAILED;
    }

    if(fclose(file) != 0)
    {
        return FAILED;
    }

    return SUCCESS;
}

int clearLogFile(const char* filepath)
{
    FILE* file;

    if( (file = fopen(filepath, "w")) == NULL)
    {
        #ifdef DEBUG
        perror("Unable to log error");
        #endif
        return FAILED;
    }

    if(fclose(file) != 0)
    {
        return FAILED;
    }

    return SUCCESS;
}