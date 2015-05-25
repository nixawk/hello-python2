#!/usr/bin/env python
# -*- coding: utf8 -*-

import threading


def worker(num):
    """thread worker function"""
    print 'worker: %s' % num
    return


threads = []
for i in range(5):
    t = threading.Thread(target=worker, args=(i, ))
    threads.append(t)
    t.start()
