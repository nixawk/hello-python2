#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Copyright (c) 2008 Doug Hellmann All rights reserved.
#


import difflib
from difflib_data import *

s1 = [ 1, 2, 3, 5, 6, 4 ]
s2 = [ 2, 3, 5, 4, 6, 1 ]

print 'Initial data:'
print 's1 =', s1
print 's2 =', s2
print 's1 == s2:', s1==s2
print

matcher = difflib.SequenceMatcher(None, s1, s2)
for tag, i1, i2, j1, j2 in reversed(matcher.get_opcodes()):

    if tag == 'delete':
        print 'Remove %s from positions [%d:%d]' % (s1[i1:i2], i1, i2)
        del s1[i1:i2]

    elif tag == 'equal':
        print 'The sections [%d:%d] of s1 and [%d:%d] of s2 are the same' % \
            (i1, i2, j1, j2)

    elif tag == 'insert':
        print 'Insert %s from [%d:%d] of s2 into s1 at %d' % \
            (s2[j1:j2], j1, j2, i1)
        s1[i1:i2] = s2[j1:j2]

    elif tag == 'replace':
        print 'Replace %s from [%d:%d] of s1 with %s from [%d:%d] of s2' % (
            s1[i1:i2], i1, i2, s2[j1:j2], j1, j2)
        s1[i1:i2] = s2[j1:j2]

    print 's1 =', s1
    print 's2 =', s2
    print

print 's1 == s2:', s1==s2
