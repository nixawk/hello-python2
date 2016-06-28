#!/usr/bin/python
# -*- coding: utf-8 -*-

import itertools


def pr(itertor):
    for i in itertor:
        print(i)


a = [1, 2, 3, 4, 5]
b = ['a', 'b', 'c', 'd', 'e']
c = ['1', '2', '3', '4', '5']

print "==== a - b ===="
print(a)
print(b)
pr(itertools.izip(a, b))

print "==== a - c ===="
print(a)
print(c)
pr(itertools.izip(a, c))

print "==== b - c ===="
print(b)
print(c)
pr(itertools.izip(b, c))
