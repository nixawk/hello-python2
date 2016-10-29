#!/usr/bin/python
# -*- coding: utf8 -*-

# http://www.celeryproject.org/
# http://docs.celeryproject.org/en/latest/getting-started/first-steps-with-celery.html
# http://docs.celeryproject.org/en/latest/userguide/tasks.html#task-result-backends

from celery import Celery
import requests

# app = Celery('tasks', broker='amqp://guest@localhost//')
app = Celery('tasks', backend='amqp', broker='amqp://')
app.conf.update(
    CELERY_IGNORE_RESULT=False,  # Default: True
)


@app.task
def add(url):
    return requests.get(url).status_code

# from tasks import add
# add.delay('https://www.google.com/')
