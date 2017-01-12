#!/usr/bin/python
# -*- coding: utf-8 -*-


class MyClass(object):
    pass


def unpredictable(obj):
    """Returns a new list containing obj.

    >>> unpredictable(MyClass())  #doctest: +ELLIPSIS
    <doctest_ellipsis.MyClass object at 0x...>
    """
    return obj
