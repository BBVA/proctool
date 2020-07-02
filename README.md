# PoC Go `ptrace`

``` console
$ strace -ff /bin/sh ./test-minimal # edited to remove noise
execve("/bin/sh", ["/bin/sh", "./test-minimal"], 0x7fffe2cf0ad0 /* 32 vars */) = 0
arch_prctl(0x3001 /* ARCH_??? */, 0x7ffeec323080) = -1 EINVAL (Invalid argument)
openat(AT_FDCWD, "/usr/lib/libswmhack.so.0.0", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/libreadline.so.8", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/libdl.so.2", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/libX11.so.6", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/libncursesw.so.6", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/libxcb.so.1", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/libXau.so.6", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/libXdmcp.so.6", O_RDONLY|O_CLOEXEC) = 3
arch_prctl(ARCH_SET_FS, 0x7fd790a1cb80) = 0
openat(AT_FDCWD, "/dev/tty", O_RDWR|O_NONBLOCK) = 3
openat(AT_FDCWD, "/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/gconv/gconv-modules.cache", O_RDONLY) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/gconv/gconv-modules", O_RDONLY|O_CLOEXEC) = 3
dsigprocmask(SIG_BLOCK, NULL, [], 8)  = 0
ioctl(-1, TIOCGPGRP, 0x7ffeec322ed4)    = -1 EBADF (Bad file descriptor)
sysinfo({uptime=13704, loads=[172288, 147264, 125728], totalram=33537720320, freeram=27961724928, sharedram=593637376, bufferram=3842048, totalswap=8589930496, freeswap=8589930496, procs=557, totalhigh=0, freehigh=0, mem_unit=1}) = 0
dsigprocmask(SIG_BLOCK, NULL, [], 8)  = 0
ioctl(2, TIOCGPGRP, [14398])            = 0
prlimit64(0, RLIMIT_NPROC, NULL, {rlim_cur=127862, rlim_max=127862}) = 0
dsigprocmask(SIG_BLOCK, NULL, [], 8)  = 0
openat(AT_FDCWD, "./test-minimal", O_RDONLY) = 3
ioctl(3, TCGETS, 0x7ffeec322e60)        = -1 ENOTTY (Inappropriate ioctl for device)
lseek(3, 0, SEEK_CUR)                   = 0
lseek(3, 0, SEEK_SET)                   = 0
prlimit64(0, RLIMIT_NOFILE, NULL, {rlim_cur=1024, rlim_max=512*1024}) = 0
fcntl(255, F_GETFD)                     = -1 EBADF (Bad file descriptor)
dup2(3, 255)                            = 255
fcntl(255, F_SETFD, FD_CLOEXEC)         = 0
fcntl(255, F_GETFL)                     = 0x8000 (flags O_RDONLY|O_LARGEFILE)
lseek(255, 0, SEEK_CUR)                 = 0
dsigprocmask(SIG_BLOCK, [INT CHLD], [], 8) = 0
lseek(255, -46, SEEK_CUR)               = 57
clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLDstrace: Process 14402 attached
, child_tidptr=0x7fd790a1ce50) = 14402
[pid 14401]dsigprocmask(SIG_SETMASK, [],  <unfinished ...>
[pid 14401] <...dsigprocmask resumed>NULL, 8) = 0
[pid 14401]dsigprocmask(SIG_BLOCK, [CHLD],  <unfinished ...>
[pid 14401] <...dsigprocmask resumed>[], 8) = 0
[pid 14401]dsigprocmask(SIG_SETMASK, [], NULL, 8) = 0
[pid 14402]dsigprocmask(SIG_SETMASK, [],  <unfinished ...>
[pid 14401]dsigprocmask(SIG_BLOCK, [CHLD],  <unfinished ...>
[pid 14402] <...dsigprocmask resumed>NULL, 8) = 0
[pid 14401] <...dsigprocmask resumed>[], 8) = 0
[pid 14401] wait4(-1,  <unfinished ...>
[pid 14402] openat(AT_FDCWD, "/tmp/parent.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
[pid 14402] dup2(3, 1)                  = 1
[pid 14402] execve("/bin/echo", ["/bin/echo", "Write", "from", "parent"], 0x55e018679d80 /* 33 vars */) = 0
[pid 14402] arch_prctl(0x3001 /* ARCH_??? */, 0x7fffc03fc6c0) = -1 EINVAL (Invalid argument)
[pid 14402] openat(AT_FDCWD, "/usr/lib/libswmhack.so.0.0", O_RDONLY|O_CLOEXEC) = 3
[pid 14402] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
[pid 14402] openat(AT_FDCWD, "/usr/lib/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
[pid 14402] openat(AT_FDCWD, "/usr/lib/libX11.so.6", O_RDONLY|O_CLOEXEC) = 3
[pid 14402] openat(AT_FDCWD, "/usr/lib/libdl.so.2", O_RDONLY|O_CLOEXEC) = 3
[pid 14402] openat(AT_FDCWD, "/usr/lib/libxcb.so.1", O_RDONLY|O_CLOEXEC) = 3
[pid 14402] openat(AT_FDCWD, "/usr/lib/libXau.so.6", O_RDONLY|O_CLOEXEC) = 3
[pid 14402] openat(AT_FDCWD, "/usr/lib/libXdmcp.so.6", O_RDONLY|O_CLOEXEC) = 3
[pid 14402] arch_prctl(ARCH_SET_FS, 0x7f1355587740) = 0
[pid 14402] openat(AT_FDCWD, "/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = 3
[pid 14402] write(1, "Write from parent\n", 18) = 18
[pid 14402] exit_group(0)               = ?
[pid 14402] +++ exited with 0 +++
<... wait4 resumed>[{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 14402
ioctl(2, TIOCGWINSZ, {ws_row=16, ws_col=146, ws_xpixel=65535, ws_ypixel=65535}) = 0
ioctl(1, TCGETS, {B38400 opost isig icanon echo ...}) = 0
openat(AT_FDCWD, "/usr/share/terminfo/x/xterm-256color", O_RDONLY) = 3
ioctl(1, TCGETS, {B38400 opost isig icanon echo ...}) = 0
ioctl(1, TCGETS, {B38400 opost isig icanon echo ...}) = 0
ioctl(1, TCGETS, {B38400 opost isig icanon echo ...}) = 0
ioctl(1, TCGETS, {B38400 opost isig icanon echo ...}) = 0
ioctl(1, TIOCGWINSZ, {ws_row=16, ws_col=146, ws_xpixel=65535, ws_ypixel=65535}) = 0
ioctl(0, TIOCGWINSZ, {ws_row=16, ws_col=146, ws_xpixel=65535, ws_ypixel=65535}) = 0
dsigprocmask(SIG_SETMASK, [], NULL, 8) = 0
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=14402, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---
wait4(-1, 0x7ffeec322490, WNOHANG, NULL) = -1 ECHILD (No child processes)
dsigreturn({mask=[]})                 = 0
dsigprocmask(SIG_BLOCK, [INT CHLD], [], 8) = 0
clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLDstrace: Process 14403 attached
, child_tidptr=0x7fd790a1ce50) = 14403
[pid 14401]dsigprocmask(SIG_SETMASK, [],  <unfinished ...>
[pid 14401] <...dsigprocmask resumed>NULL, 8) = 0
[pid 14401]dsigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0
[pid 14401]dsigprocmask(SIG_SETMASK, [],  <unfinished ...>
[pid 14401] <...dsigprocmask resumed>NULL, 8) = 0
[pid 14401]dsigprocmask(SIG_BLOCK, [CHLD],  <unfinished ...>
[pid 14403]dsigprocmask(SIG_SETMASK, [],  <unfinished ...>
[pid 14401] <...dsigprocmask resumed>[], 8) = 0
[pid 14403] <...dsigprocmask resumed>NULL, 8) = 0
[pid 14401] wait4(-1,  <unfinished ...>
[pid 14403]dsigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0
[pid 14403]dsigprocmask(SIG_SETMASK, [], NULL, 8) = 0
[pid 14403] openat(AT_FDCWD, "/tmp/child.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
[pid 14403] dup2(3, 1)                  = 1
[pid 14403] execve("/bin/echo", ["/bin/echo", "Write", "from", "child"], 0x55e018691cc0 /* 33 vars */) = 0
[pid 14403] arch_prctl(0x3001 /* ARCH_??? */, 0x7fffd827c6c0) = -1 EINVAL (Invalid argument)
[pid 14403] openat(AT_FDCWD, "/usr/lib/libswmhack.so.0.0", O_RDONLY|O_CLOEXEC) = 3
[pid 14403] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
[pid 14403] openat(AT_FDCWD, "/usr/lib/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
[pid 14403] openat(AT_FDCWD, "/usr/lib/libX11.so.6", O_RDONLY|O_CLOEXEC) = 3
[pid 14403] openat(AT_FDCWD, "/usr/lib/libdl.so.2", O_RDONLY|O_CLOEXEC) = 3
[pid 14403] openat(AT_FDCWD, "/usr/lib/libxcb.so.1", O_RDONLY|O_CLOEXEC) = 3
[pid 14403] openat(AT_FDCWD, "/usr/lib/libXau.so.6", O_RDONLY|O_CLOEXEC) = 3
[pid 14403] openat(AT_FDCWD, "/usr/lib/libXdmcp.so.6", O_RDONLY|O_CLOEXEC) = 3
[pid 14403] arch_prctl(ARCH_SET_FS, 0x7f81409dc740) = 0
[pid 14403] openat(AT_FDCWD, "/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = 3
[pid 14403] write(1, "Write from child\n", 17) = 17
[pid 14403] exit_group(0)               = ?
[pid 14403] +++ exited with 0 +++
<... wait4 resumed>[{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 14403
ioctl(2, TIOCGWINSZ, {ws_row=16, ws_col=146, ws_xpixel=65535, ws_ypixel=65535}) = 0
dsigprocmask(SIG_SETMASK, [], NULL, 8) = 0
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=14403, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---
wait4(-1, 0x7ffeec322490, WNOHANG, NULL) = -1 ECHILD (No child processes)
dsigreturn({mask=[]})                 = 0
dsigprocmask(SIG_BLOCK, [CHLD], [], 8) = 0
dsigprocmask(SIG_SETMASK, [], NULL, 8) = 0
exit_group(0)                           = ?
+++ exited with 0 +++
```

## Libraries to be tested

- [ ] https://github.com/tfogal/ptrace/blob/master/ptrace.go
- [ ] https://github.com/hjr265/ptrace.go

## Notes

- We've discarded C because Go provides the `syscall` library which provides
  what we need, while at the same time is easier and safer to use.
- Although we are using Go there are not too many advantages on the portability
  side due to the low level of programming required in this project. We are
  dealing with architecture-specific things like registers and offsets to
  structures.
