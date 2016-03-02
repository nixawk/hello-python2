#!/usr/bin/env python
# -*- coding: utf8 -*-

# Greenlets
# The primary pattern used in gevent is the Greenlet, a lightweight coroutine
# provided to Python as a C extension module. Greenlets all run inside of OS
# process for the main program but are scheduled cooperatively.

# Only one greenlet is ever running at any given time.

# This differs from any of the real parallelism constructs provided by
# [multiprocessing] or [threading] libraries which do spin processes and POSIX
# threads which are scheduled by the operating system and are truly parallel.

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
thread2 = gevent.spawn(foo, 'I live !', 2)

# Lambda expressions
thread3 = gevent.spawn(lambda x: (x+1), 2)

threads = [thread1, thread2, thread3]

# Block until all threads complete .
gevent.joinall(threads)
