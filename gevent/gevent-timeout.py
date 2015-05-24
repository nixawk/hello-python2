#!/usr/bin/env python
# -*- coding: utf8 -*-

import gevent
from gevent import Timeout


seconds = 10

timeout = Timeout(seconds)
timeout.start()


def wait():
    gevent.sleep(10)

try:
    gevent.spawn(wait).join()
except Timeout:
    print('Could not complete')
