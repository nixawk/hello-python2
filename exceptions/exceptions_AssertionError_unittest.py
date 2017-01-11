#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Copyright (c) 2008 Doug Hellmann All rights reserved.
#


import unittest


class AssertionExample(unittest.TestCase):

    def test(self):
        self.failUnless(False)

unittest.main()
