#ifndef _ELF_DYNAMIC_INFO_
#define _ELF_DYNAMIC_INFO_

#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>

struct user_regs_struct* getRegisterValues(int pid);

#endif