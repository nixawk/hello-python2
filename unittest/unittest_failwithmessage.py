#!/usr/bin/python
# -*- coding: utf-8 -*-

import unittest


class FailureMessageTest(unittest.TestCase):
    def testFail(self):
        self.failIf(True, 'failure message goes here')


if __name__ == '__main__':
    unittest.main()
