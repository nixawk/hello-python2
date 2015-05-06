#!/usr/bin/env python
# -*- coding: utf8 -*-

import threading
import logging
import random
import time

logging.basicConfig(level=logging.DEBUG,
                    format='(%(threadName)-10s) %(message)s')


class Counter(object):
    def __init__(self, start=0):
        self.lock = threading.Lock()
        self.value = start

    def increment(self):
        logging.debug('Waiting for lock')
        self.lock.acquire()
        try:
            logging.debug('Acquired lock')
            self.value = self.value + 1
        finally:
            logging.debug('release lock')
            self.lock.release()


def worker(c):
    for i in range(2):
        pause = random.random()
        logging.debug('Sleeping %0.02f', pause)
        time.sleep(pause)
        c.increment()

    logging.debug('Done')


counter = Counter()
for i in range(2):
    t = threading.Thread(target=worker, args=(counter,))
    t.start()


logging.debug('Waiting for worker threads')
main_thread = threading.currentThread()
for t in threading.enumerate():
    if t is not main_thread:
        t.join()

logging.debug('Counter: %d', counter.value)
