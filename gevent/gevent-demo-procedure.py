#!/usr/bin/env python
# -*- coding: utf8 -*-

import gevent


def foo():
    print('Running in foo')
    gevent.sleep(0)
    print('Emplict context switch to foo again')


def bar():
    print('Emplict context to bar')
    gevent.sleep(0)
    print('Implict switch switch back to bar')

gevent.joinall([
    gevent.spawn(foo),
    gevent.spawn(bar)
])
