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

- Only supported syscalls are `openat` and `execve`.
- No children of the surveilled process will be monitored after the dead of its parent.
