#!/usr/bin/python
# -*- coding: utf-8 -*-

import unittest


class SimplisticTest(unittest.TestCase):

    def test(self):
        self.failUnless(True)


if __name__ == '__main__':
    unittest.main()
