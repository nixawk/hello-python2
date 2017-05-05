#!/usr/bin/python
# -*- coding: utf-8 -*-

import contextlib


# Creating context managers the traditional way, by writing a class with
# __enter__() and __exit__() methods, is not difficult. But sometimes it
# is more overhead than you need just to manage a trivial bit of context.

# In those sorts of situations, you can use the contextmanager() decorator
#  to convert a generator function into a context manager.

@contextlib.contextmanager
def context_manager(value):
    yield value


if __name__ == '__main__':
    iterator = [0, 1, 2, 3, 4]
    with context_manager(iterator) as cm:
        for _ in cm: print(_)