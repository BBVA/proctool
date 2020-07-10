#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void)
{
    int wstatus;

    if (!fork()) {
        execl("/usr/bin/uname", "");
    }
    waitpid(-1, &wstatus, 0);
    puts("Done!");
}
