#!/usr/bin/env python
# -*- coding: utf8 -*-


from ctypes import *


class POINT(Structure):
    _fields_ = [("x", c_int),
                ("y", c_int)]

if __name__ == "__main__":
    point = POINT(10, 20)
    print "x: %d y:%d\n" % (point.x, point.y)
