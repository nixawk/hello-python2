#!/usr/bin/env python
# -*- coding: utf8 -*-

import threading
import time
import logging


logging.basicConfig(level=logging.DEBUG,
                    format='(%(threadName)-10s) %(message)s')


def worker(msg):
    logging.debug('worker says "%s"' % msg)
    return

t1 = threading.Timer(3, worker, ("hello world", ))
t1.setName('t1')

t2 = threading.Timer(3, worker, ("hello python", ))
t2.setName('t2')

logging.debug('starting timers')
t1.start()
t2.start()

logging.debug('waiting before canceling %s', t2.getName())
time.sleep(2)
logging.debug('canceling %s', t2.getName())
t2.cancel()
logging.debug('done')
