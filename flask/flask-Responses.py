#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
## Responses

The return value from a view function is automatically converted into a response object for you.
If the return value is a string it's converted into a response object with the string as response body,
a 200 OK status code and a text/html mimetype. The logic that Flask applies to converting return values
into response objects is as follows:

1. If a response object of the correct type is returned it's directly returned from the view.
2. If it's a string, a response object is created with that data and the default parameters.
3. If a tuple is returned the items in the tuple can provide extra information. Such tuples have to
   be in the form (response, status, headers) or (response, headers) where at least one item has
   to be in the tuple. The status value will override the status code and headers can be a list or
   directory of additional header values.
4. If none of that works, Flask will assume the return value is a valid WSGI application and convert
   that into a response object.
"""

from flask import Flask
from flask import make_response
from flask import render_template_string


app = Flask(__name__)


@app.route('/')
def index():
    return "Home Page"


@app.errorhandler(404)
def page_not_found(error):
    resp = make_response(render_template_string("{{ errmsg }}", errmsg=str(error)))
    resp.headers['X-Something'] = 'A Value'
    return resp


if __name__ == '__main__':
    app.run()