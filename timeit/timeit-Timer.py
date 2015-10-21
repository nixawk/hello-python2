#!/usr/bin/python
# -*- coding: utf-8 -*-

import timeit


# code test
t = timeit.Timer(stmt="print('main statement')", setup="print('setup')")
print(t.timeit(3))

print("--------")
print(t.repeat(3, 3))


# function test
def test1():
    return [str(i) for i in range(100)]


def test2():
    return map(str, range(100))


t1 = timeit.Timer(stmt='test1()', setup='from __main__ import test1')
print(t1.timeit(100000))

t2 = timeit.Timer(stmt='test2()', setup='from __main__ import test2')
print(t2.timeit(100000))
