#!/usr/bin/env python
# -*- coding: utf8 -*-


import gevent
from gevent.queue import Queue, Empty


tasks = Queue(maxsize=3)


def worker(n):
    try:
        while True:
            task = tasks.get(timeout=1)
            print('Worker %s got task %s' % (n, task))
            gevent.sleep(0)
    except Empty:
        print('Quitting time!')


def boss():
    """
    Boss will wait to bound out work until a individual worker is free
    since the maxsize of the task queue is 3.
    """

    for i in xrange(1, 10):
        tasks.put(i)

    print('Assigned al work in iteration 1')

    for i in xrange(10, 20):
        tasks.put(i)

    print('Assigned al work in iteration 2')


gevent.joinall([
    gevent.spawn(boss),
    gevent.spawn(worker, 'steve'),
    gevent.spawn(worker, 'john'),
    gevent.spawn(worker, 'bob'),
])
