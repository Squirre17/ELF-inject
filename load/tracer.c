#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>

int main(int argc, char **argv) {
    pid_t child;
    long orig_eax, eax;
    int status;
    struct user_regs_struct regs;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program>\n", argv[0]);
        exit(1);
    }

    child = fork();

    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[1], &argv[1]);
    } else {
        wait(&status);

        while (WIFSTOPPED(status)) {
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            printf("RIP: 0x%lx\n", regs.rip);

            ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
            wait(&status);
        }
    }

    return 0;
}
