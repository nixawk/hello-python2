#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Copyright (c) 2008 Doug Hellmann All rights reserved.
#


import binascii


def hexlify(string, nbytes=1):
    """Format text string as a sequence of nbyte long values"""
    step = nbytes * 2   # FF FF
    hexstr = binascii.hexlify(string)

    for index in range(0, len(hexstr), step):
        yield hexstr[index:index+step]


def to_hex(string, nbytes):
    return " ".join(hexlify(string, nbytes))


if __name__ == '__main__':
    print to_hex('abcdef', 1)
    print to_hex('abcdef', 2)
    print to_hex('abcdef', 3)
    print to_hex('abcdef', 4)
