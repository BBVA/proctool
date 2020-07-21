#include <sys/types.h>
#include <unistd.h>

void main()
{
    for (int i=0; i<256; i++) {
        if (!fork()) break;
    }
}

