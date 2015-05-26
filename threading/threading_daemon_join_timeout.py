#!/usr/bin/env python
# -*- coding: utf8 -*-

import threading
import time
import logging


logging.basicConfig(level=logging.DEBUG,
                    format='(%(threadName)-10s) %(message)s')


def daemon():
    logging.debug('Starting')
    time.sleep(2)
    logging.debug('Exiting')


def non_daemon():
    logging.debug('Starting')
    logging.debug('Exiting')


d = threading.Thread(name='daemon', target=daemon)
d.setDaemon(True)

t = threading.Thread(name='non-daemon', target=non_daemon)

d.start()
t.start()

# d.join(1)
d.join(3)
print 'd.isAlive()', d.isAlive()
t.join()
