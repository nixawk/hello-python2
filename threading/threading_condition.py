#!/usr/bin/env python
# -*- coding: utf8 -*-

import logging
import threading
import time


logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s (%(threadName)-2s) %(message)s')


def consumer(cond):
    """Wait for the condition and use the resource"""
    logging.debug('Starting consumer thread')

    threading.currentThread()

    with cond:
        cond.wait()
        logging.debug('Resource is available to consumer')


def producer(cond):
    """set up the resource to be used by the consumer"""
    logging.debug('Starting producer thread')
    with cond:
        logging.debug('Making resource available')
        cond.notifyAll()


condition = threading.Condition()
c1 = threading.Thread(name='c1', target=consumer,
                      args=(condition,))

c2 = threading.Thread(name='c2', target=consumer,
                      args=(condition,))
p1 = threading.Thread(name='p', target=producer,
                      args=(condition,))

c1.start()
time.sleep(2)
c2.start()
time.sleep(2)
p1.start()
