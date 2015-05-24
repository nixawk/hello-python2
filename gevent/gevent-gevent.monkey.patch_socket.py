#!/usr/bin/env python
# -*- coding: utf8 -*-

import gevent.monkey
gevent.monkey.patch_socket()

import gevent
import urllib2
from timeit import Timer


def fetch(pid):
    response = urllib2.urlopen('http://search.yahoo.com',
                               timeout=3)
    result = response.read()

    print('Process %s: %s' % (pid, len(result)))
    return len(result)


def synchronous():
    for i in range(1, 10):
        fetch(i)


def asynchronous():
    threads = [gevent.spawn(fetch, i) for i in range(1, 10)]
    gevent.joinall(threads)


print('Synchronous:')
t = Timer('synchronous', 'from __main__ import synchronous')
print "%3.20f" % t.repeat(repeat=1, number=3)[0]

print('Asynchronous:')
t = Timer('asynchronous', 'from __main__ import asynchronous')
print "%3.20f" % t.repeat(repeat=1, number=3)[0]
