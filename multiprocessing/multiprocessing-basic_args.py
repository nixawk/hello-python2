#!/usr/bin/env python
# -*- coding: utf8 -*-

import multiprocessing


def worker(num):
    """thread worker function"""
    print "Worker: %d" % num
    return

if __name__ == '__main__':
    jobs = []
    for i in range(5):
        p = multiprocessing.Process(target=worker, args=(i,))
        jobs.append(p)
        p.start()
