#!/usr/bin/python
# -*- coding: utf-8 -*-

## Our Project

# Project layout:

# proj/__init__.py
#     /celery.py
#     /tasks.py

# ---------------------------
# proj/celery.py

"""
from __future__ import absolute_import, unicode_literals
from celery import Celery

app = Celery('proj',
             broker='amqp://',
             backend='amqp://',
             include=['proj.tasks'])

# Optional configuration, see the application user guide.
app.conf.update(
    result_expires=3600,
)

if __name__ == '__main__':
    app.start()
"""

# In this module you created our Celery instance (sometimes referred to as the app).
# To use Celery within your project you simply import this instance.

# The broker argument specifies the URL of the broker to use.
# http://docs.celeryproject.org/en/latest/getting-started/first-steps-with-celery.html#celerytut-broker

# The  backend argument specifies the result backend to use,
# http://docs.celeryproject.org/en/latest/getting-started/first-steps-with-celery.html#celerytut-keeping-results

# The include argument is a list of modules to import when the worker starts. You
# need to add our tasks module here so that the worker is able to find our tasks.

# ---------------------------
# proj/tasks.py

"""
from __future__ import absolute_import, unicode_literals
from .celery import app


@app.task
def add(x, y):
    return x + y


@app.task
def mul(x, y):
    return x * y


@app.task
def xsum(numbers):
    return sum(numbers)
"""

## Starting the worker

# The celery program can be used to start the worker (you need to  run the worker
# in the directory above proj).

# $ celery -A proj worker -l info


## Stopping the worker

# To stop the worker simply hit Control-C. A list of signals supported by the worker is
# detailed in the Workers Guide.

# http://docs.celeryproject.org/en/latest/userguide/workers.html#guide-workers


## In the background

# In production you'll want to run the worker in the background, this is described in detail in the
# daemonization tutorial.
# http://docs.celeryproject.org/en/latest/userguide/daemonizing.html#daemonizing

# The daemonization scripts uses the celery multi command to start one or more workers in the background:

# $ celery multi start w1 -A proj -l info
# $ celery multi restart w1 -A proj -l info
# $ celery stop restart w1 -A proj -l info
# $ celery stopwait restart w1 -A proj -l info

# By default it'll create pid and log files in the current directory, to protect against
# multiple workers launching on top of each other you're encouraged to put these in
# dedicated directory.

# $ mkdir -p /var/run/celery
# $ mkdir -p /var/log/celery
# $ celery multi start w1 -A proj -l info --pidfile=/var/run/celery/%n.pid --logfile=/var/log/celery/%n%I.log
