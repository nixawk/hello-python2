#!/usr/bin/python
# -*- coding: utf8 -*-

"""
Greenlet objects

Greenlet is a light-weight cooperatively-scheduled execution unit.
To start a new greenlet , pass the target function and its arguments
to Greenlet constructor and call start().

    >>> import gevent
    >>> g = gevent.Greenlet(myfunction, 'arg1', 'arg2', kwarg1=1)
    >>> g.start()

or use classmethod [spawn()] which is a shortcut that does the same.

    >>> g = Greenlet.spawn(myfunction, 'arg1', 'arg2', kwarg1=1)
"""

import gevent
import logging

logging.basicConfig(level=logging.INFO, format="%(message)s")


def foo1():
    g = gevent.Greenlet(logging.info, "abcdefg")
    g.start()
    g.join()


def foo2():
    g = gevent.Greenlet.spawn(logging.info, "123456")
    gevent.joinall([g])


if __name__ == "__main__":
    foo1()
    foo2()
