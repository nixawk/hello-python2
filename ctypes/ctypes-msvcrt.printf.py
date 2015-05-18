#!/usr/bin/env python
# -*- coding: utf8 -*-

from ctypes import *


def win_printf():
    msvcrt = cdll.msvcrt
    message_string = "Hello String\n"
    msvcrt.printf("Testing: %s", message_string)


def linux_printf():
    libc = cdll.LoadLibrary("libc.so.6")
    # libc = CDLL("libc.so.6")
    message_string = "Hello String\n"
    libc.printf("Testing: %s", message_string)

linux_printf()
