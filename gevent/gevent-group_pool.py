#!/usr/bin/env python
# -*- coding: utf8 -*-


import gevent
from gevent import getcurrent
from gevent.pool import Group


group = Group()


def hello_from(n):
    print('Size of group %s' % len(group))
    print('Hello from Greenlet %s' % id(getcurrent()))


group.map(hello_from, xrange(3))


def intensive(n):
    gevent.sleep(3 - n)
    return 'task', n


print('Ordered')


ogroup = Group()
for i in ogroup.imap(intensive, xrange(3)):
    print (i)


print('Unordered')


igroup = Group()
for i in igroup.imap_unordered(intensive, xrange(3)):
    print(i)
