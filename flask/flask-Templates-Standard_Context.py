#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
## Standard Context

The following global variable are available within Jinja2 templates by default:


- config

	The current configuration object (flask.config)

- request

	The current request object (flask.request).
	This variable is unavailable if the template was rendered without an active request context.

- session

	The current session object (flask.session). This variable is unavailable if the template was
	rendered without an active request context.

- g

	The request-bound object for global variable (flask.g). This variable is unavailable if the
	template was rendered without an active request context.

- url_for()

	The flask.url_for() function.

- get_flashed_messages()

	The flask.get_flashed_messages() function.

"""

from flask import Flask


app = Flask(__name__)
print(app.config)