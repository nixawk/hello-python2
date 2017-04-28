#!/usr/bin/python
# -*- coding: utf-8 -*-

# Aplication

# The first thing you need is a Celery instance. We call this the Celery application or just
# app for short. As this instance is used as the entry-point for everything you want to do in
# Celery, like creating tasks and managing workers, it must be possible for other modules to
# import it.

from celery import Celery

# The first argument to Celery is the name of the curent module, this only needed so names
# can be automatically generated when the tasks are defined in the __main__ module.

# The second argument is the broker keyword argument, specifying the URL of the message broker
# you want to use.

app = Celery('tasks', broker='mongodb://localhost')


@app.task
def add(x, y):
	return x + y


## References

# http://docs.celeryproject.org/en/latest/getting-started/first-steps-with-celery.html#celerytut-broker