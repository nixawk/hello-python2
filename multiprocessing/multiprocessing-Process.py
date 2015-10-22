#!/usr/bin/python
# -*- coding: utf-8 -*-

from multiprocessing import Process
import os


def f(name):
    print 'process id   : ', os.getpid()
    print 'process name : ', name


if __name__ == '__main__':
    p = Process(target=f, args=('Process1', ))
    p.start()
    p.join()
