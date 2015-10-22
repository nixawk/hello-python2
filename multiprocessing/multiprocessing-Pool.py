#!/usr/bin/python
# -*- coding: utf-8 -*-

from multiprocessing import Pool


def f(x):
    return x * x


if __name__ == "__main__":
    # pool = Pool(5)
    pool = Pool(processes=4)            # start 4 worker process
    result = pool.apply_async(f, [10])  # evaluate "f(10)" asyncchronously
    print result.get(timeout=1)
    print pool.map(f, range(10))

"""
Note:
    the methods of a pool should only ever be used by the process which created
    it.
"""
