#!/usr/bin/env python
# -*- coding: utf8 -*-

from ctypes import *
import sys


def printf():
    # windows
    if "win" in sys.platform:
        libc = cdll.LoadLibrary("msvcrt")
    # linux
    elif "linux" in sys.platform:
        libc = cdll.LoadLibrary("libc.so.6")

    if libc:
        return libc.printf
    else:
        return None


class Param(object):
    def __init__(self, number):
        self._as_parameter_ = number

_printf = printf()
if _printf:
    param = Param(20)
    _printf("[*] number is %d\n", param)
