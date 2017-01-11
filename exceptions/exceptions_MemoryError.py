#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Copyright (c) 2008 Doug Hellmann All rights reserved.
#


import itertools

# Try to create a MemoryError by allocating a lot of memory
l = []
for i in range(3):
    try:
        for j in itertools.count(1):
            print i, j
            l.append('*' * (2**30))
    except MemoryError:
        print '(error, discarding existing list)'
        l = []
