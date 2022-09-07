#include "../Modules/ELFinfo/elfinfo.h"
#include "../Modules/Dynamic/elfdynamic.h"

#define TEST32 "/home/calum/Test_Files/while32"
#define TEST64 "/home/calum/Test_Files/while64"

void ptrace_test();

int main(int argc, char const *argv[])
{
    ptrace_test();
    return 0;
}

void ptrace_test()
{
    pid_t PID;

    PID = fork();


    if(PID == 0) /* Child process */
    {
        // Do some random calculations
        int i = 0;
        while(1)
        {
            sleep(1);
            ++i;
        }
    }

    else
    {
        struct user_regs_struct* regs;

        regs = getRegisterValues(PID); /* Get the register values of the child process. */

        printf("0x%x\n", regs->r10);
    }
}