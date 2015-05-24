#!/usr/bin/env python
# -*- coding: utf8 -*-

import gevent
from gevent import Greenlet


def foo(message, n):
    """
    Each thread will be passed the message, and n in arguments
    in its initialization
    """
    gevent.sleep(n)
    print(message)


# Initialize a new Greenlet instance running the named function foo
thread1 = Greenlet.spawn(foo, 'Hello', 1)

# Wrapper for creating and running a new Greenlet from the named
# function foo, with the passed arguments
threads = gevent.spawn(foo, 'I live !', 2)

# Lambda expressions
thread3 = gevent.spawn(lambda x: (x+1), 2)

# Block until all threads complete .
gevent.joinall(threads)
