#!/usr/bin/python
# -*- coding: utf8 -*-

import logging
import gevent
from gevent.threadpool import ThreadPool


logging.basicConfig(level=logging.INFO, format="%(message)s")


def callback_(args):
    for arg in args:
        logging.info(arg.strip())


def foo(args):
    return args


if __name__ == "__main__":
    tp = ThreadPool(20)
    f = open('/tmp/test.txt')
    greenlets = [tp.map_async(foo, f, callback=callback_)]
    gevent.joinall(greenlets)
