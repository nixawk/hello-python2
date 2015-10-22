#!/usr/bin/python
# -*- coding: utf-8 -*-

from multiprocessing import Process, Lock


def f(l, i):
    l.acquire()
    print 'hello world', i
    l.release()


if __name__ == '__main__':
    lock = Lock()

    for num in range(10):
        p = Process(target=f, args=(lock, num))
        p.start()
