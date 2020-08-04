Prerequisites
-------------

* Nix


Testing
-------

```bash
nix-shell --command "make test"
```

Caveats
-------

- Only supported syscalls are `openat` and `execve`.  `open` is NOT at the moment.
- No children of the surveilled process will be monitored after the dead of its parent.
