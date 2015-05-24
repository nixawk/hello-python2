#!/usr/bin/env python
# -*- coding: utf8 -*-

import gevent


def win():
    return 'You win!'


def fail():
    raise Exception('You fail at failing')


winner = gevent.spawn(win)
loser = gevent.spawn(fail)

print(winner.started)  # True
print(loser.started)   # True

# Exceptions raised in the Greenlet , stay inside the Greenlet
try:
    gevent.joinall([winner, loser])
except Exception as e:
    print('This will never be reached')

print(winner.value)    # 'You win!'
print(loser.value)     # None

print(winner.ready())  # True
print(loser.ready())   # True

print(winner.successful())  # True
print(loser.successful())   # False

# The excpetion raised in fail, will not propogate outside the
# greenlet. A stack trace will be printed to stdout but it
# will not unwind the stack of the parent.

print(loser.exception)

# It is possible though to raise the exception again outside
# raise loser exception
# or with
# loser.get()
