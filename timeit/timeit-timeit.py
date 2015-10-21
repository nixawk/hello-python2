#!/usr/bin/python
# -*- coding: utf-8 -*-

import timeit


"""

https://docs.python.org/2/library/timeit.html

The timeit module reduces the impact of startup or shutdown costs
on the time calculation by executing the code repeatedly.

    $ python -m timeit '"-".join(str(n) for n in range(100))'
    10000 loops, best of 3: 39.9 usec per loop

    $ python -m timeit '"-".join([str(n) for n in range(100)])'
    10000 loops, best of 3: 34.4 usec per loop

    $ python -m timeit '"-".join(map(str, range(100)))'
    10000 loops, best of 3: 28.2 usec per loop

"""


def test():
    """Stupid test function"""
    L = []
    for i in range(100):
        L.append(i)


if __name__ == '__main__':
    print(timeit.timeit(
        "char in text",    # stmt
        setup="char = 'l'; text = 'hello'",
        number=1000000     # number
    ))
    print(timeit.timeit("test()", setup="from __main__ import test"))
