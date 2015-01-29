#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
abspath  --

realpath -- Return the canonical path of the specified filename,
            eliminating any symbolic links encountered in the path
            (if they are supported by the operating system)

relpath  --
"""

import os
import inspect


def getpath0():
    return os.path.dirname(os.path.abspath(__file__))


def getpath1():
    return os.path.dirname(os.path.normpath(__file__))


def getpath2():
    return os.path.dirname(os.path.realpath(__file__))


def getpath3():
    return os.path.dirname(os.path.relpath(__file__))


def getpath4():
    return os.path.dirname(
        os.path.abspath(inspect.getsourcefile(lambda _: None)))

print "abcpath:\t%s" % getpath0()
print "normpath:\t%s" % getpath1()
print "realpath:\t%s" % getpath2()
print "relpath:\t%s" % getpath3()
print "getsourcefile:\t%s" % getpath4()
