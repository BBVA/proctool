#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>


int main(int argc, char *argv[]) {
    int times = 1;

    if (argc >= 2) {
        times = atoi(argv[1]);
    }

    char path[1024];
    if (!readlink("/proc/self/exe", path, 1024)) {
        return 1;
    }

    for (int i=0; i<times; i++) {
        close(openat(AT_FDCWD, path, O_RDONLY));
    }
}
