# TODO: rename fixture files to express the actual behavior and not the test intent

from datetime import datetime
from datetime import timedelta
from itertools import zip_longest, count
import hashlib
import json
import os
import pickle
import shlex
import signal
import stat
import string
import subprocess
import tempfile

import hypothesis
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


@pytest.mark.xfail(reason="This cannot be achieved with the current design")
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
    fixture = f"{PROJECT}/tests/fixtures/openat-self-multiple-times"
    _, log = proctool(fixture, str(times))

    found = 0
    for entry in log:
        try:
            if entry["path"] == fixture and entry["hash"] and entry["syscallStopPoint"] == "SYSCALL_STOP_POINT_OPENAT_RETURN":
                found += 1
        except KeyError:
            pass

    assert found == times


@given(st.integers(min_value=0, max_value=255))
def test_detect_open(times):
    fixture = f"{PROJECT}/tests/fixtures/open-self-multiple-times"
    _, log = proctool(fixture, str(times))

    found = 0
    for entry in log:
        try:
            if entry["path"] == fixture and entry["hash"] and entry["syscallStopPoint"] == "SYSCALL_STOP_POINT_OPEN_RETURN":
                found += 1
        except KeyError:
            pass

    assert found == times


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

        _, log = proctool(program_path)

        for entry in log:
            try:
                hash = entry['hash']
                input_hashes.remove(hash)
            except KeyError:
                # Log entry is not per hashed file or hash is not on input_hashes
                pass

        assert len(input_hashes) == 0, str(input_hashes)


@given(
    outputs=st.dictionaries(
        keys=st.text(alphabet=string.ascii_lowercase),
        values=st.binary()))
def test_capture_outputs_of_a_process(outputs):
    with tempfile.TemporaryDirectory() as tmpdir:
        output_hashes = set()
        for content in outputs.values():
            output_hashes.add(hashlib.md5(content).hexdigest())

        program_data = {'outputs': outputs}

        program_path = os.path.join(tmpdir, 'program.py')
        with open(program_path, 'w') as program:
            program.write(f"""#!/usr/bin/env python
import os.path

DATA={repr(program_data)}
TMPDIR={repr(tmpdir)}

for filename, content in DATA['outputs'].items():
    with open(os.path.join(TMPDIR, 'output_'+filename), 'wb') as f:
        f.write(content)

""")
            os.fchmod(program.fileno(), stat.S_IRWXU)

        _, log = proctool(program_path)

        for entry in log:
            try:
                hash = entry['hash']
                output_hashes.remove(hash)
            except KeyError:
                # Log entry is not per hashed file or hash is not on output_hashes
                pass

        assert len(output_hashes) == 0, str(output_hashes)

@given(
    outputs=st.dictionaries(
        keys=st.text(alphabet=string.ascii_lowercase),
        values=st.binary()))
def test_capture_truncated_outputs_of_a_process(outputs):
    with tempfile.TemporaryDirectory() as tmpdir:
        output_hashes = set()
        for content in outputs.values():
            output_hashes.add(hashlib.md5(content).hexdigest())

        program_data = {'outputs': outputs}

        program_path = os.path.join(tmpdir, 'program.py')
        with open(program_path, 'w') as program:
            program.write(f"""#!/usr/bin/env python
import os.path

DATA={repr(program_data)}
TMPDIR={repr(tmpdir)}

for filename, content in DATA['outputs'].items():
    with open(os.path.join(TMPDIR, 'output_'+filename), 'wb+') as f:
        f.write(content)

""")
            os.fchmod(program.fileno(), stat.S_IRWXU)

        _, log = proctool(program_path)

        for entry in log:
            try:
                hash = entry['hash']
                output_hashes.remove(hash)
            except KeyError:
                # Log entry is not per hashed file or hash is not on output_hashes
                pass

        assert len(output_hashes) == 0, str(output_hashes)

@given(
    inputsoutputs=st.dictionaries(
        keys=st.text(alphabet=string.ascii_lowercase),
        values=st.tuples(st.binary(), st.binary())))
def test_capture_mixed_inputs_and_outputs_of_a_process(inputsoutputs):
    with tempfile.TemporaryDirectory() as tmpdir:
        input_hashes = set()
        output_hashes = set()
        for name, (previous_content, next_content) in inputsoutputs.items():
            with open(os.path.join(tmpdir, f"inputoutput_{name}"), 'wb') as tmpfile:
                tmpfile.write(previous_content)
                input_hashes.add(hashlib.md5(previous_content).hexdigest())
                final = bytes(n if n is not None else p for p, n in zip_longest(previous_content, next_content))
                output_hashes.add(hashlib.md5(final).hexdigest())

        program_data = {'outputs': {filename: next_content for filename, (_, next_content) in inputsoutputs.items()}}

        program_path = os.path.join(tmpdir, 'program.py')
        with open(program_path, 'w') as program:
            program.write(f"""#!/usr/bin/env python
import os.path

DATA={repr(program_data)}
TMPDIR={repr(tmpdir)}

for filename, next_content in DATA['outputs'].items():
    with open(os.path.join(TMPDIR, 'inputoutput_'+filename), 'rb+') as f:
        f.write(next_content)

""")
            os.fchmod(program.fileno(), stat.S_IRWXU)

        _, log = proctool(program_path)

        for entry in log:
            try:
                hash = entry['hash']
            except KeyError:
                # Log entry is not per hashed file or hash is not on input_hashes
                pass
            else:
                try:
                    # TODO: differentiate in the log file which files are inputs and outputs
                    input_hashes.remove(hash)
                except KeyError:
                    pass
                try:
                    output_hashes.remove(hash)
                except KeyError:
                    pass

        assert (len(input_hashes), len(output_hashes)) == (0, 0), f"Input: {input_hashes}\nOutput: {output_hashes}"



@st.composite
def openfile(draw,
              mode=st.sampled_from(('rb', 'wb', 'wb+', 'rb+')),
              precontent=st.binary(),
              postcontent=st.binary()):
    mode_ = draw(mode)
    return ('openfile',
            {'path': str(draw(st.uuids())),
             'mode': mode_,
             'precontent': draw(precontent) if 'r' in mode_ else None,
             'postcontent': draw(postcontent) if set('+w')&set(mode_) else None})

program = st.lists
fork = lambda p: st.tuples(st.just('fork'), st.fixed_dictionaries({'instructions': program(p)}))
clone = lambda p: st.tuples(st.just('clone'), st.fixed_dictionaries({'instructions': program(p)}))
operations=lambda: st.recursive(openfile(), lambda p: st.one_of(fork(p), clone(p)))


def timeout(signum, frame):
    raise TimeoutError("test took too long")

@pytest.mark.wip
@given(instructions=st.lists(operations()))
@hypothesis.settings(
    deadline=timedelta(seconds=10),
    # suppress_health_check=hypothesis.HealthCheck.all()
)
def test_capture_inputs_and_outputs_in_a_process_tree(instructions):
    with tempfile.TemporaryDirectory() as tmpdir:
        input_hashes = set()
        output_hashes = set()

        def create_input_files(ins):
            for i in ins:
                op, params = i
                if op == 'openfile':
                    precontent, postcontent = params['precontent'], params['postcontent']
                    if precontent is not None:
                        input_hashes.add(hashlib.md5(precontent).hexdigest())
                        with open(os.path.join(tmpdir, 'file_' + params['path']), 'wb+') as f:
                            f.write(precontent)
                    if postcontent is not None:
                        if precontent is not None:
                            final = bytes(n if n is not None else p for p, n in zip_longest(precontent, postcontent))
                            output_hashes.add(hashlib.md5(final).hexdigest())
                        else:
                            output_hashes.add(hashlib.md5(postcontent).hexdigest())
                elif op in ('fork', 'clone'):
                    create_input_files(params['instructions'])
                else:  # nope
                    pass

        create_input_files(instructions)

        program = f"""#!/usr/bin/python
import os
import sys
import threading

DATA={repr(instructions)}
TMPDIR={repr(tmpdir)}
current = []

class OPS:
    @staticmethod
    def openfile(path, mode, postcontent=None, **_):
        with open(os.path.join(TMPDIR, 'file_' + path), mode=mode) as fh:
            if postcontent is not None:
                fh.write(postcontent)

    @staticmethod
    def fork(instructions, **_):
        pid = os.fork()
        if pid == 0:
            follow_instructions(instructions)
            sys.exit(0)
        else:
            os.waitpid(pid, 0)

    @staticmethod
    def clone(instructions, **_):
        t=threading.Thread(target=follow_instructions, args=(instructions,), daemon=False)
        t.start()
        t.join()

    @staticmethod
    def nope(**_):
        pass

def run_instruction(i):
    global current
    op, params = i
    # print(f"Running: {{current}} => {{op}} {{params}}")
    current[-1] = current[-1] + 1
    return getattr(OPS, op)(**params)


def follow_instructions(instructions):
    global current
    current.append(0)
    for instruction in instructions:
        run_instruction(instruction)


if __name__ == '__main__':
    follow_instructions(DATA)

"""

        program_path = os.path.join(tmpdir, 'program.py')
        with open(program_path, 'w+') as f:
            f.write(program)
            os.fchmod(f.fileno(), stat.S_IRWXU)

        signal.signal(signal.SIGALRM, timeout)
        signal.alarm(10)
        _, log = proctool(program_path)

        for entry in log:
            try:

                hash = entry['hash']
            except KeyError:
                # Log entry is not per hashed file or hash is not on input_hashes
                pass
            else:
                try:
                    # TODO: differentiate in the log file which files are inputs and outputs
                    input_hashes.remove(hash)
                except KeyError:
                    pass
                try:
                    output_hashes.remove(hash)
                except KeyError:
                    pass

        assert (len(input_hashes), len(output_hashes)) == (0, 0), f"Input: {input_hashes}\nOutput: {output_hashes}"
