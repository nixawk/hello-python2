#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
## Accessing Request Data

For web application it's crucial to react to the data a client sends to the server. In Flask
this information is provided by the global request object. If you have some experience with
Python you might be wondering how that object can be global and how Flask manages to still
be threadsafe.
"""

from flask import Flask
from flask import request


app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    assert request.path == '/'
    assert request.method == 'POST'
    return "Hello Flask"


if __name__ == '__main__':
    app.run()