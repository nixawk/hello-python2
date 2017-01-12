#!/usr/bin/python
# -*- coding: utf-8 -*-

import unittest


def raise_error(*args, **kwds):
    print args, kwds
    raise ValueError('Invalid value:' + str(args) + str(kwds))


class ExceptionTest(unittest.TestCase):

    def testTrapLocally(self):
        try:
            raise_error('a', b='c')
        except ValueError:
            pass
        else:
            self.fail('Did not see ValueError')

    def testFailUnlessRaises(self):
        self.failUnlessRaises(ValueError, raise_error, 'a', b='c')


if __name__ == '__main__':
    unittest.main()
