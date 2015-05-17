#!/usr/bin/env python
# -*- coding: utf8 -*-

import os
import sys


def func(arg, dirname, fnames):
    """Directory tree walk callback function"""
    for fname in fnames:
        if fname.endswith('.py'):
            print "%s%s%s" % (dirname, os.sep, fname)

if __name__ == '__main__':
    """list file with .py ext"""
    if len(sys.argv) != 2:
        print "\n\tpython %s dirpath/\n" % sys.argv[0]
    else:
        path = os.path.realpath(sys.argv[1])
        os.path.walk(path, func, None)
