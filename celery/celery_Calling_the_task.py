#!/usr/bin/python
# -*- coding: utf-8 -*-

# To call our task you can use the delay() method.
# This is a handy shortcut to the [apply_async()] method that gives greater
# control of the task execution

# >>> from exploit import add
# >>> add.delay(4, 4)

# The task has now been processed by the worker you started earlier, and you can
# verify that by looking at the worker console output.

# Calling a task returns an [AsyncResult] instance: this can be used to check the 
# state of the task, wait for the task to finish, or get its return value (or if the
# task failed, the exception and traceback)

# Results aren't enabled by default, so if you want to do RPC or keep track of task
# results in a database you have to confiure Celery to use a result backend. This is
# described by the next section.