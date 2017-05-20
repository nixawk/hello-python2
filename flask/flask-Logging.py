#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
## Logging

Sometimes you might be in a situation where you deal with data that should be correct,
but actually is not. For example you may have some client-side code that sends an HTTP
request to the server but it’s obviously malformed. This might be caused by a user
tampering with the data, or the client code failing. Most of the time it’s okay to
reply with 400 Bad Request in that situation, but sometimes that won’t do and the
code has to continue working.
"""

from flask import Flask


app = Flask(__name__)


@app.route('/')
def index():
	app.logger.info('hello flask logging')
	return "Home Page"


if __name__ == '__main__':
	app.run(debug=True)