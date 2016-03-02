#!/usr/bin/python
# -*- coding: utf8 -*-

# The core idea of concurrency is that a larger task can be broken down into a
# collection of subtasks which are scheduled to run [simultaneously] or
# [asynchronously], instead of one at a time or [synchronously]. A switch
# between the two subtasks is known as a context switch.

# A context switch in gevent is done through yielding. In this example we have
# two contexts which yield to each other through invoking gevent.sleep(0).


import gevent


def foo():
    print('Running in foo')
    gevent.sleep(0)
    print('Explicit context switch to foo again')


def bar():
    print('Explicit context to bar')
    gevent.sleep(0)
    print('Implicit context switch back to bar')

gevent.joinall([
    gevent.spawn(foo),
    gevent.spawn(bar)
])

# The real power of comes when we use it for network and IO bound functions
# which can be cooperatively scheduled. Gevent has taken care of all the
# details to ensure that your network libraries will implicitly yield their
# greenlet contexts whenever possible. I cannot stress enough what a powerful
# idiom this is. But maybe an example will illustrate.
