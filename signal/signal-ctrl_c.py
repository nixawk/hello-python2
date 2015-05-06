#!/usr/bin/env python
# -*- coding: utf-8 -*-

import signal


def handler(signum, frame):
    print "capture ctrl+c"


signal.signal(signal.SIGINT, handler)

while True:
    pass
