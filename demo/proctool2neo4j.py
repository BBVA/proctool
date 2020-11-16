#!/usr/bin/env python3

from functools import reduce
from itertools import *
import csv
import json
import operator as op
import os
import sys
from os.path import basename

from py2neo import *
from progressbar import progressbar


try:
    BUILD=sys.argv[2]
except IndexError:
    print(f"Usage {sys.argv[0]} <proctool-log.json> build-name")
    sys.exit(1)


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


class ProcessCache(dict):
    def __missing__(self, key):
        self[key] = Node("Process", pid=key, build=BUILD)
        return self[key]


class FileCache(dict):
    def __missing__(self, key):
        self[key] = Node("File", path=key, basename=basename(key), build=BUILD)
        return self[key]


processes = ProcessCache()
files = FileCache()

FORKS = Relationship.type("FORKS")
READS = Relationship.type("READS")
WRITES = Relationship.type("WRITES")
EXECS = Relationship.type("EXECS")

rss = list()


with open(sys.argv[1], 'r') as raw:
    for num, line in enumerate(progressbar(raw), 1):
        if "STOPCAUSE_SURVEILLED_SYSCALL" not in line or "SYSCALL_STOP_POINT_UNMONITORED" in line:
            continue

        try:
            e = json.loads(line)
        except Exception as err:
            raise ValueError(f"Reading json line {num}") from err

        try:
            if e["stopCause"] == "STOPCAUSE_SURVEILLED_SYSCALL":
                if e["syscallStopPoint"] in ("SYSCALL_STOP_POINT_OPEN_RETURN", "SYSCALL_STOP_POINT_OPENAT_RETURN"):
                    path, mode, pid = e["path"], e["mode"], e["traceePid"]
                    if mode == "O_RDWR":
                        rss.append(READS(processes[pid], files[path]))
                        rss.append(WRITES(processes[pid], files[path]))
                    elif mode == "O_WRONLY":
                        rss.append(WRITES(processes[pid], files[path]))
                    elif mode == "O_RDONLY":
                        rss.append(READS(processes[pid], files[path]))
                    else:
                        raise ValueError(f"Invalid mode {mode}")

                elif e["syscallStopPoint"] ==  "SYSCALL_STOP_POINT_EXECVE_CALL":
                    path, pid = e["path"], e["traceePid"]
                    rss.append(EXECS(processes[pid], files[path]))
                elif e["syscallStopPoint"] ==  "SYSCALL_STOP_POINT_CLONE_CALL":
                    child, parent = e["childPid"], e["traceePid"]
                    rss.append(FORKS(processes[parent], processes[child]))
        except KeyError:
            pass

conn=Graph(user='neo4j', password='test')
for group in progressbar(list(grouper(rss, 100))):
    conn.create(reduce(op.ior, (x for x in group if x is not None)))

