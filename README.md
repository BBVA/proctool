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

- `openat` and `execve` are the only supported syscalls.
- No children of the surveilled process will be monitored after the dead of its parent.
