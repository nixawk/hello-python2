
# Grouping multiple tests in a class

# Once you start to have more than a few tests it often makes sense to group
# tests logically, in a classes and modules. Let's write a class containing two
# tests:


class TestClass:
    def test_one(self):
        x = "this"
        assert 'h' in x

    def test_two(self):
        x = "hello"
        assert hasattr(x, 'check')

# The two tests are found because of the standard Conventions for Python test
# discovery. There is no need to subclass anything. We can simply run the
#  module by passing its filename:

"""
$ py.test -q test_class.py
.F
======= FAILURES ========
_______ TestClass.test_two ________

self = <test_class.TestClass object at 0xdeadbeef>

    def test_two(self):
        x = "hello"
>       assert hasattr(x, 'check')
E       assert hasattr('hello', 'check')

test_class.py:8: AssertionError
1 failed, 1 passed in 0.12 seconds
"""
