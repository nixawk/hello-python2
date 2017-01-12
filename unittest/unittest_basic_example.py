#!/usr/bin/python
# -*- coding: utf-8 -*-

import unittest


# https://docs.python.org/2/library/unittest.html

# The test case and fixture concepts are supported through the TestCase and
# FunctionTestCalse classes; the former should be used when creating new tests,
# and the latter can be used when integrating existing test code with a
# unittest-driven framework.

# Test suites are implemented by the TestSuite class. This class allows
# individual tests and test suites to be aggregated; when the suite is executed
# ,all tests added directly to the suite and in "Child" test suites are run.

# setUp() and tearDown() methods allow you to define instructions that will be
# executed before and after each test method.

class TestStringMethods(unittest.TestCase):

    def test_upper(self):
        self.assertEqual('foo'.upper(), 'FOO')

    def test_isupper(self):
        self.assertTrue('FOO'.isupper())
        self.assertTrue('Foo'.isupper())

    def test_split(self):
        s = 'hello world'
        self.assertEqual(s.split(), ['hello', 'world'])
        # check that s.split fails when the separator is not a string
        with self.assertRaises(TypeError):
            s.split(2)


if __name__ == '__main__':
    # unittest.main()

    # Instead of unittest.main(), there are other ways to run the tests with
    # a finer level of control, less terse output, and no requirement to be
    # run from the command line.
    suite = unittest.TestLoader().loadTestsFromTestCase(TestStringMethods)
    unittest.TextTestRunner(verbosity=2).run(suite)
