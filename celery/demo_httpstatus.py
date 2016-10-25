#!/usr/bin/python
# -*- coding: utf8 -*-

# http://www.celeryproject.org/

from celery import Celery
import requests

# app = Celery('tasks', broker='amqp://guest@localhost//')
app = Celery('tasks', backend='amqp', broker='amqp://guest@localhost//')


@app.task
def add(url):
    return requests.get(url).status_code

# from tasks import add
# add.delay('https://www.google.com/')
