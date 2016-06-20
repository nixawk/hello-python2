
# Asserting that a certain exception is raised

# If you want to assert that some code raises an exception you can use
# the raises helper:

import pytest


def f():
    raise SystemExit(1)


def test_exception():
    with pytest.raises(SystemExit):
        f()

# Running it with, this time in "quite" reporting mode:

"""
$ py.test -q test_sysexit.py
.
1 passed in 0.12 seconds
"""
