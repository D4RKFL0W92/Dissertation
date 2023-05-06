#include "./logging.h"

int logEvent(const char* filepath, const char* func_name, const char* cause)
{
  FILE* file;

  if( (file = fopen(filepath, "a+")) == NULL)
  {
    #ifdef DEBUG
    perror("Unable to log error");
    #endif
    return ERR_UNKNOWN;
  }

  if(fprintf(file, "%s failed while calling %s\n", func_name, cause) < 0)
  {
    #ifdef DEBUG
    perror("Unable to write log to file.");
    #endif
    return ERR_UNKNOWN;
  }

  if(fclose(file) != 0)
  {
    return ERR_UNKNOWN;
  }

  return ERR_NONE;
}

int clearLogFile(const char* filepath)
{
  FILE* file;

  if( (file = fopen(filepath, "w")) == NULL)
  {
    #ifdef DEBUG
    perror("Unable to log error");
    #endif
    return ERR_UNKNOWN;
  }

  if(fclose(file) != 0)
  {
    return ERR_UNKNOWN;
  }

  return ERR_NONE;
}