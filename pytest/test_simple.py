# Let's create a first test file with a simple test function:
# $ python -m pytest test_simple.py
# $ py.test test_simple.py


def func(x):
    return x + 1


def test_answer():
    assert func(3) == 5

"""
$ py.test
======= test session starts ========
platform linux -- Python 3.5.1, pytest-2.9.2, py-1.4.31, pluggy-0.3.1
rootdir: $REGENDOC_TMPDIR, inifile:
collected 1 items

test_sample.py F

======= FAILURES ========
_______ test_answer ________

    def test_answer():
>       assert func(3) == 5
E       assert 4 == 5
E        +  where 4 = func(3)

test_sample.py:5: AssertionError
======= 1 failed in 0.12 seconds ========
"""

# We got a failure report because our little func(3) call did not return 5.

# You can simply use the assert statement for asserting test expectations.
# pytest's Advanced assertion will intellgently report intermediate values of
# the assert expression freeing you from the need to the many names of
# JUnit legacy methods.
