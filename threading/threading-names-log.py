#!/usr/bin/env python
# -*- coding: utf8 -*-

import logging
import threading
import time


logging.basicConfig(
    level=logging.DEBUG,
    format='[%(levelname)s] %(threadName)-10s %(message)s')


def worker():
    logging.debug('%s Starting' % threading.currentThread().getName())
    time.sleep(2)
    logging.debug('%s Exiting' % threading.currentThread().getName())


def service():
    logging.debug('%s Starting' % threading.currentThread().getName())
    time.sleep(3)
    logging.debug('%s Exiting' % threading.currentThread().getName())


if __name__ == '__main__':
    t = threading.Thread(name='service', target=service)
    w = threading.Thread(name='worker', target=worker)
    w2 = threading.Thread(target=worker)

    t.start()
    w.start()
    w2.start()
