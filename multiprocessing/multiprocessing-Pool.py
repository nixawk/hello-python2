#!/usr/bin/python
# -*- coding: utf-8 -*-

from multiprocessing import Pool


def f(x):
    a, b = x
    return a + b


if __name__ == "__main__":
    p = Pool(5)
    print(p.map(f, [(1, 2), (2, 3), (3, 4)]))
