#!/usr/bin/python
# -*- coding: utf-8 -*-

# You now run the worker by executing our program with the worker argument.

# $ celery -A tasks worker --loglevel=info

# In production you'll want to run the worker in the background as daemon. To do this
# you need to use the tools provided by your platform, or something like [supervisord]

# For a complete listing of the command-line options available, do:

# http://supervisord.org/
# http://docs.celeryproject.org/en/latest/userguide/daemonizing.html#daemonizing