# TODO: rename fixture files to express the actual behavior and not the test intent

from datetime import datetime
import hashlib
import json
import os
import pickle
import shlex
import stat
import string
import subprocess
import tempfile

from hypothesis import given
from hypothesis import strategies as st
import pytest


PROJECT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def proctool(*args):
    command = [f"{PROJECT}/bin/proctool"] + list(args)
    exitcode, lines = subprocess.getstatusoutput(" ".join([shlex.quote(c) for c in command]))
    def decode():
        for l in lines.splitlines():
            yield json.loads(l)

    return (exitcode, list(decode()))


def test_detect_biffs_dead():
    _, log = proctool(f"{PROJECT}/tests/fixtures/01-honor-child-last-wish")
    for entry in log:
        if entry.get('stopCause', None) == 'STOPCAUSE_BIFF_EXIT':
            return
    else:
        assert False, "STOPCAUSE_BIFF_EXIT not found"


def test_detect_biffs_dead_once():
    _, log = proctool(f"{PROJECT}/tests/fixtures/01-honor-child-last-wish")
    deads = 0

    for entry in log:
        if entry.get('stopCause', None) == 'STOPCAUSE_BIFF_EXIT':
            deads+=1

    assert deads == 1


def test_honor_child_last_wish():
    exitcode, _ = proctool(f"{PROJECT}/tests/fixtures/01-honor-child-last-wish")
    assert exitcode == 42



@pytest.mark.skip("This cannot be achieved with the current design")
def test_waits_for_surveilled_event_if_biff_dies_prematurely():
    before = datetime.now()
    proctool("/bin/sh", "-c", "/bin/sleep 3 & disown")
    after = datetime.now()
    assert (after - before).seconds >= 3


@given(st.integers(min_value=1, max_value=42))
def test_follow_parent_forks(number):
    """
    $ strace -f ./tests/fixtures/02-follow-parent-forks 12 2>&1 | grep exited | wc -l
    13
    """
    _, log = proctool(f"{PROJECT}/tests/fixtures/02-follow-parent-forks", str(number))

    surveilled_exit = set()
    for entry in log:
        if entry.get('stopCause', None) == 'STOPCAUSE_SURVEILLED_EXIT':
            surveilled_exit.add(entry['traceePid'])

    assert len(surveilled_exit) == number+1


@given(st.integers(min_value=1, max_value=42))
def test_follow_children_forks(number):
    """
    $ strace -f ./tests/fixtures/03-follow-children-forks 12 2>&1 | grep exited | wc -l
    13
    """
    _, log = proctool(f"{PROJECT}/tests/fixtures/03-follow-children-forks", str(number))

    surveilled_exit = set()
    for entry in log:
        if entry.get('stopCause', None) == 'STOPCAUSE_SURVEILLED_EXIT':
            surveilled_exit.add(entry['traceePid'])

    assert len(surveilled_exit) == number+1


@given(st.integers(min_value=0, max_value=255))
def test_detect_openat(times):
    fixture = f"{PROJECT}/tests/fixtures/open-self-multiple-times"
    _, log = proctool(fixture, str(times))
    
    found = 0
    for entry in log:
        try:
            if entry["path"] == fixture and entry["hash"] and entry["syscallStopPoint"] == "SYSCALL_STOP_POINT_OPENAT_RETURN":
                found += 1
        except KeyError:
            pass

    assert found == times



@pytest.mark.skip
@given(
    inputs=st.dictionaries(
        keys=st.text(alphabet=string.ascii_lowercase),
        values=st.binary()))
def test_capture_inputs_of_a_process(inputs):
    with tempfile.TemporaryDirectory() as tmpdir:
        input_hashes = set()
        for name, content in inputs.items():
            with open(os.path.join(tmpdir, f"input_{name}"), 'wb') as tmpfile:
                tmpfile.write(content)
                input_hashes.add(hashlib.md5(content).hexdigest())

        program_data = {'inputs': list(inputs.keys())}

        program_path = os.path.join(tmpdir, 'program.py')
        with open(program_path, 'w') as program:
            program.write(f"""#!/usr/bin/env python
import os.path

DATA={repr(program_data)}
TMPDIR={repr(tmpdir)}

for filename in DATA['inputs']:
    with open(os.path.join(TMPDIR, 'input_'+filename), 'rb'):
        pass

""")
            os.fchmod(program.fileno(), stat.S_IRWXU)

        exitcode, log = proctool(program_path)

        for entry in log:
            try:
                hash = entry['hash']
                input_hashes.remove(hash)
            except KeyError:
                # Log entry is not per hashed file or hash is not on input_hashes
                pass

        try:
            assert len(input_hashes) == 0, str(input_hashes)
        except:
            import pdb
            pdb.set_trace()
