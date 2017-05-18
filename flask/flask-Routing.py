#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Routing

Modern web applications have beautiful URLs. This helps people remember the URLs,
which is especially handy for applications that are used from mobile devices with
slower netowrk connections. If the user can directly go to the desired page without
having to hit the index page it is more likely they will like the page and come back
next time.

route() decorator is used to bind a function to a URL. 
"""

from flask import Flask


app = Flask(__name__)


@app.route('/')
def index():
	return "Index Page"


@app.route('/hello')
def hello():
	return "Hello, World"


if __name__ == '__main__':
	app.run()