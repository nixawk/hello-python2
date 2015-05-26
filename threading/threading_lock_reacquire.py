#!/usr/bin/env python
# -*- coding: utf8 -*-


import threading


lock = threading.Lock()


print 'First try :', lock.acquire()
print 'Second try :', lock.acquire(0)
