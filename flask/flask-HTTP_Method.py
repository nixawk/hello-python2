#!/usr/bin/python
# -*- coding: utf-8 -*-

from flask import Flask
from flask import request


app = Flask(__name__)


"""
HTTP (the protocol web applications are speaking) knows different methods for accessing URLs.
By default, a route only answers to GET requests, but that can be changed by providing the methods
argument to the route() decorator. Here are some examples:
"""

@app.route('/login', methods=['GET', 'POST'])
def login():
    return 'HTTP POST REQUEST' if request.method == 'POST' else 'HTTP GET REQUEST'


if __name__ == '__main__':
    app.run()