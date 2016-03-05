#!/usr/bin/python
# -*- coding: utf8 -*-

# apply(func, args=None, kwds=None)
# Rough equivalent of the apply() builtin function, blocking until
# the result is ready and returning it.
# The func will usually, but not always, be run in a way that
# allows the current greenlet to switch out (for example, in a new
# greenlet or thread, depending on implementation). But if the current
# greenlet or thread is already one that was spawned by this pool, the pool may
# choose to immediately run the func synchronously.

from gevent.threadpool import ThreadPool


def foo(abc):
    print(abc)


tp = ThreadPool(10)
for i in range(50):
    tp.apply(foo, args=(i,))

    # Rough quivalent of the apply() builtin function blocking until
    # the result is ready and returning it.
