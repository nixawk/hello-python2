#!/usr/bin/env python
# -*- coding: utf8 -*-

import gevent
from gevent import Timeout


time_to_wait = 5  # seconds


class TooLong(Exception):
    pass

with Timeout(time_to_wait, TooLong):
    gevent.sleep(10)
