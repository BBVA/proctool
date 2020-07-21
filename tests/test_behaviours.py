import json
import os.path
import shlex
import subprocess

from hypothesis import given
from hypothesis import strategies as st
import pytest


PROJECT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def proctool(*args):
    command = [f"{PROJECT}/bin/proctool"] + list(args)
    exitcode, lines = subprocess.getstatusoutput(" ".join([shlex.quote(c) for c in command]))
    return (exitcode, [json.loads(l) for l in lines.splitlines()])


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


@given(st.integers(min_value=1, max_value=42))
def test_follow_forks(number):
    """
    $ strace -f ./tests/fixtures/02-follow-forks 12 2>&1 | grep exited | wc -l
    13
    """
    _, log = proctool(f"{PROJECT}/tests/fixtures/02-follow-forks", str(number))

    surveilled_exit = set()
    for entry in log:
        if entry.get('stopCause', None) == 'STOPCAUSE_SURVEILLED_EXIT':
            surveilled_exit.add(entry['traceePid'])

    assert len(surveilled_exit) == number+1 
