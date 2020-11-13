ProcTool
========

`proctool` is a proof-of-concept tool implementing "Artifact Tracing via I/O Monitoring".

Prerequisites
-------------

* Nix


Installation
------------

```bash
$ nix-shell
$ make install
```

Testing
-------

```bash
$ nix-shell
$ make test
```

Caveats
-------

- Current implementation is based on `strace`.  A high performance hit is expected.
- `openat` and `execve` are the only supported syscalls.
- No children of the surveilled process will be monitored after the dead of its parent.
