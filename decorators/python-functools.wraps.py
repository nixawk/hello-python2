#!/usr/bin/python
# -*- coding: utf-8 -*-

from functools import wraps


def decorator_one(func):
    @wraps(func)
    def wrapper(*args, **kwds):
        func(*args, **kwds)
    return wrapper


def decorator_two(func):
    def wrapper(*args, **kwds):
        func(*args, **kwds)
    return wrapper


@decorator_one
def foo_one():
    """foo_one docstring
    """
    print("hello foo_one")


@decorator_two
def foo_two():
    """foo_two docstring
    """
    print("hello foo_two")


if __name__ == '__main__':
    print(foo_one.__name__)  # foo_one
    print(foo_one.__doc__)   # foo_one docstring

    print(foo_two.__name__)  # wrapper
    print(foo_two.__doc__)   # None


# http://stackoverflow.com/questions/308999/what-does-functools-wraps-do