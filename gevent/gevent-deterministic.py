#!/usr/bin/python
# -*- coding: utf8 -*-

# As mentioned previously, greelets are deterministic. Given the same
# configuration of greenlets and the same set of inputs, they always
# produce the same output. For eample, let's spread a task across a
# multiprocessing pool and compare its results to the one of a gevent pool.

import time
from multiprocessing.pool import Pool as p1
from gevent.pool import Pool as p2


def echo(i):
    time.sleep(0.001)
    return i

# Non deterministic process pool

p = p1(10)
run1 = [a for a in p.imap_unordered(echo, xrange(10))]
run2 = [a for a in p.imap_unordered(echo, xrange(10))]
run3 = [a for a in p.imap_unordered(echo, xrange(10))]
run4 = [a for a in p.imap_unordered(echo, xrange(10))]

print(run1 == run2 == run3 == run4)

p = p2(10)
run1 = [a for a in p.imap_unordered(echo, xrange(10))]
run2 = [a for a in p.imap_unordered(echo, xrange(10))]
run3 = [a for a in p.imap_unordered(echo, xrange(10))]
run4 = [a for a in p.imap_unordered(echo, xrange(10))]

print(run1 == run2 == run3 == run4)

# Even through gevent is normally deterministic, sources of
# non-determinism can creep into your program when you begin
# to interact with outside services such as sockets and files.
# Thus even though green threads are a form of "deterministic concurrency",
# they still can experience some of the same problems that POSIX threads
# and processes experience.

# The perennial problem involved with concurrency is known as a race
# condition. Simply put, a race condition occurs when two concurrent
# threads / processes depend on some shared resource but also attempt
# to modify this value. This results in resources which values become
# time-dependent on the execution order. This is a problem, and in general
# one should very much try to avoid race conditions since they result
# in a globally non-deterministic program behavior.
