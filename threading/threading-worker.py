#!/usr/bin/env python
# -*- coding: utf8 -*-

import threading
import logging
import time

logging.basicConfig(level=logging.DEBUG,
                    format='[%(levelname)s] (%(threadName)-10s) %(message)s')


def worker(_id):
    logging.debug("Worker: %d" % i)
    time.sleep(1)
    return


[threading.Thread(name="thread-%03d" % i, target=worker, args=(i,)).start() for i in range(6)]
