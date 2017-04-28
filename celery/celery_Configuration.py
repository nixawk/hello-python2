#!/usr/bin/python
# -*- coding: utf-8 -*-

## Configuration

# Celery, like a consumer appliance, doesn't need much to be operated. It has an input
# and an output, where you must connect the input to a broker and maybe the output to
# a result backend if so wanted. But if you look closely at the back there's a lid
# revealing loads of sliders, dials, and buttons: this is configuration.

# The default configuration should be good enough for most uses, but there are many things
# to tweak so Celery works just the way you want it to. Reading about the options available
# is a good idea to get familiar with what can be configured. You can read about the options
# in the Configuration and defaults reference.

# http://docs.celeryproject.org/en/latest/userguide/configuration.html#configuration

# If you're configuring many settings at once you can use update:

# app.conf.update(
#     task_serializer='json',
#     accept_content=['json'],  # Ignore other content
#     result_serializer='json',
#     timezone='Europe/Oslo',
#     enable_utc=True,
# )

# For larger projects using a dedicated configuration module is useful, in fact you're discouraged
# from hard coding periodic task intervals and task routing options, as it's much better to keep
# this in a certralized location, and especially for libraries it makes it possible for users to
# control how they want your tasks to behave, you can also imagine your SysAdmin making simple changes
# to the configuration in the event of system trouble.

# You can tell your Celery instance to use a configuration module, by calling the app.config_from_object() method.

# >>> app.config_from_object('celeryconfig')

# A module named celeryconfig.py must then be available to load from the current directory or on the Python
# path, it could look like this:

broker_url = 'mongodb://'
result_backend = 'mongodb://localhost/test'

task_serializer = 'json'
result_serializer = 'json'
accept_content = ['json']
timezone = 'Europe/Oslo'
enable_utc = True

# For a complete reference of configuration options, see Configuration and defaults.
# http://docs.celeryproject.org/en/latest/userguide/configuration.html#configuration

# To demonstrate the power of configuration files, this is how you'd route a misbehaving
# task to a dedicated queue.

task_routes = {
	"tasks.add": 'low-priority'
}

# Or instead of routing it you could rate limit the task instead, so that only 10 tasks of this
# type can be processed in a minute (10/m):

task_annotations = {
	'tasks.add': {'rate_limit': '10/m'}
}

# http://docs.celeryproject.org/en/latest/userguide/routing.html#guide-routing
# http://docs.celeryproject.org/en/latest/userguide/configuration.html#std:setting-task_annotations
# http://docs.celeryproject.org/en/latest/userguide/monitoring.html#guide-monitoring