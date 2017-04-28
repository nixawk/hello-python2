#!/usr/bin/python
# -*- coding: utf-8 -*-

# If you want to keep track of the tasks' states, Celery needs to store or send
# the states somewhere. There are several built-in backends to choose from:
# SQLAlchemy/Django/ORM, Memcahed, Redis, RPC (RabbitMQ/AMQP), and - or define your own.

# app = Celery('tasks', backend='rpc://', broker='pyamqp://')

# (or via the result_backend settings if you choose to use a configuration module.)
# http://docs.celeryproject.org/en/latest/userguide/configuration.html#std:setting-result_backend

app = Celery('tasks', backend="mongodb://localhost/test", broker="mongodb://")


@app.task
def add(x, y):
    return x + y

# Now with the result backend configured, let's call the task again. This time you'll
# hold on to the AsyncResult instance returned when you call a task.

# >>> from exploit import add
# >>> result = add.delay(4, 5)

# The ready() method returns whether the task has finished processing or not:

# >>> result.ready()
# False

# You can wait for the result to cpmplete, but this is rarely used since it turns the
# asynchronous call into a synchronous one:

# >>> result.get(timeout=1)
# 8

# In case the task raised an exception, get() will re-raise the exception, but you can
# override this by specifying the propagate argument.

# >>> result.get(propagate=False)

# If the task raised an exception you can also gain access to the original traceback:

# >>> result.traceback
