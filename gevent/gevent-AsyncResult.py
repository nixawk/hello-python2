#!/usr/bin/env python
# -*- coding: utf8 -*-

import gevent
from gevent.event import AsyncResult


a = AsyncResult()


def setter():
    """
    After 3 seconds set the result of a
    """
    gevent.sleep(3)
    a.set('Hello !')


def waiter():
    """
    After 3 value the get call will unlock after the setter
    puts a value into the AsyncResult.
    """
    print(a.get())


gevent.joinall([
    gevent.spawn(setter),
    gevent.spawn(waiter)
])
