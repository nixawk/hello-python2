#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Copyright (c) 2008 Doug Hellmann All rights reserved.
#


from difflib import SequenceMatcher

A = " abcd"
B = "abcd abcd"

print 'A = %r' % A
print 'B = %r' % B

print '\nWithout junk detection:'

s = SequenceMatcher(None, A, B)
i, j, k = s.find_longest_match(0, 5, 0, 9)
print '  i = %d' % i
print '  j = %d' % j
print '  k = %d' % k
print '  A[i:i+k] = %r' % A[i:i+k]
print '  B[j:j+k] = %r' % B[j:j+k]

print '\nTreat spaces as junk:'

s = SequenceMatcher(lambda x: x==" ", A, B)
i, j, k = s.find_longest_match(0, 5, 0, 9)
print '  i = %d' % i
print '  j = %d' % j
print '  k = %d' % k
print '  A[i:i+k] = %r' % A[i:i+k]
print '  B[j:j+k] = %r' % B[j:j+k]

