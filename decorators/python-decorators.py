#!/usr/bin/python
# -*- coding: utf-8 -*-

## What is a Decorator ?

# A decorator is the name used for a software design pattern. Decorators dynamically alter the 
# functionality of a function, method, or class without having to directly use subclasses or change
# the source code of the function being decorated.


def decorator_one(func):
    print("decorator_one ----1111----")
    def wrapper(*arg, **kwds):
        print("decorator_one ----3333----")
        func(*arg, **kwds)
    print("decorator_one ----2222----")
    return wrapper


def decorator_two(func):
    print("decorator_two ----AAAA----")
    def wrapper(*arg, **kwds):
        print("decorator_two ----CCCC----")
        func(*arg, **kwds)
    print("decorator_two ----BBBB----")
    return wrapper


@decorator_two
@decorator_one
def foo():
    print("this is a demo string.")


if __name__ == '__main__':
    foo()

    # ----AAAA----
    # ----CCCC----
    # ----BBBB----
    # this is a demo string.


# References
# https://wiki.python.org/moin/PythonDecorators
# http://en.wikipedia.org/wiki/Decorator_pattern
# http://www.python.org/peps/pep-0318.html