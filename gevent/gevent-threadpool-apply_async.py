#!/usr/bin/python
# -*- coding: utf8 -*-

# apply_async(func, args=None, kwds=None, callback=None)
# A variant of the apply() method which returns a Greenlet object
# If callback is specified, then it should be a callable which accepts
# a single argument. When the result becomes ready callback is applied
# to it (unless the call failed).

from gevent.threadpool import ThreadPool
from gevent.pool import Pool
import gevent
import logging


logging.basicConfig(level=logging.INFO, format="%(funcName)s %(message)16s")


def foo(abc):
    logging.info(abc)
    return abc


def callback_(args):
    logging.info(args)
    return args


def invalid():
    tp = ThreadPool(10)

    # It's invalid to use callback.
    greenlets = [tp.apply_async(foo, args=(i, ), kwds=None, callback=callback_)
                 for i in xrange(1, 300)]
    gevent.joinall(greenlets)


def valid():
    tp = Pool(10)
    for i in xrange(1, 300):
        tp.add(tp.apply_async(foo, args=(i, ), kwds=None, callback=callback_))
    tp.join()


if __name__ == "__main__":
    invalid()
    # valid()
