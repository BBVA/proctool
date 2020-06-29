# PoC Go `ptrace`

```console
$ strace -ff /bin/sh ./test-minimal 2>&1 | grep -e execve -e openat -e clone
execve("/bin/sh", ["/bin/sh", "./test-minimal"], 0x7ffcbdd07450 /* 82 vars */) = 0
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/libreadline.so.8", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/libdl.so.2", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/libncursesw.so.6", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/dev/tty", O_RDWR|O_NONBLOCK) = 3
openat(AT_FDCWD, "/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/gconv/gconv-modules.cache", O_RDONLY) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/gconv/gconv-modules", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "./test-minimal", O_RDONLY) = 3
clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLDstrace: Process 11337 attached
[pid 11337] openat(AT_FDCWD, "/tmp/parent.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
[pid 11337] execve("/bin/echo", ["/bin/echo", "Write", "from", "parent"], 0x5639c085b140 /* 82 vars */) = 0
[pid 11337] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
[pid 11337] openat(AT_FDCWD, "/usr/lib/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
[pid 11337] openat(AT_FDCWD, "/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = 3
clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f61db593e50) = 11338
[pid 11338] openat(AT_FDCWD, "/tmp/child.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
[pid 11338] execve("/bin/echo", ["/bin/echo", "Write", "from", "child"], 0x5639c085c330 /* 82 vars */) = 0
[pid 11338] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
[pid 11338] openat(AT_FDCWD, "/usr/lib/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
[pid 11338] openat(AT_FDCWD, "/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = 3

```

## Libraries to be tested

- [ ] https://github.com/tfogal/ptrace/blob/master/ptrace.go
- [ ] https://github.com/hjr265/ptrace.go
