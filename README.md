Prerequisites
-------------

* Nix


Testing
-------

```bash
$ nix-shell
$ make
```

Caveats
-------

- Only supported syscalls are `openat` and `execve`.  `open` is NOT at the moment.
- No children of the surveilled process will be monitored after the dead of its parent.
- No distinction of file type is made at this moment.  This means that it tries to hash *everything*, including character devices (`/dev/tty` is specially painful)
