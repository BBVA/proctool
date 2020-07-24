#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	if (fork())
	{
		int wstatus;
		wait(&wstatus);
		return WEXITSTATUS(wstatus);
	}

	if (execv(argv[1], &argv[1])==-1)
	{
		return 127;
	}
}
