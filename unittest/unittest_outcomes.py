#!/usr/bin/python
# -*- coding: utf-8 -*-

# ok    : The test pass
# FAIL  : The test does not pass, and raises an AssertionError exception.
# ERROR : The test raises an exception other than AssertionError.

import unittest


class OutcomesTest(unittest.TestCase):

    def testPass(self):
        return

    def testFail(self):
        self.failIf(True)

    def testError(self):
        raise RuntimeError('Test error!')


if __name__ == '__main__':
    unittest.main()
