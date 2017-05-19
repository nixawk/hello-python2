#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
## Cookies

To access cookies you can use the cookies attribute. To set cookies you can use the
set_cookie method of response objects. The cookies attribute of request objects is a
dictionary with all the cookies the client transmits. If you want to use sessions, do
not use the cookies directly but instead use the Session in Flask that add some security
on top of cookies for you.
"""

from flask import Flask
from flask import request
from flask import make_response
from flask import render_template_string


app = Flask(__name__)


@app.route('/')
def index():
    resp = make_response(render_template_string("hello cookie: {{ cookie }}",
        cookie=str(request.cookies)
    ))
    resp.set_cookie('username', 'admin')
    return resp
    
    # use cookies.get(key) instead of cookies[key] to not get a
    # KeyError if the cookie is missing.

    # Note that cookies are set on response objects. Since you normally just return strings
    # from the view functions Flask will convert then them into response objects for you.
    # If you explicitly want to do that you can the [make_response()] function and then modify it.


if __name__ == '__main__':
    app.run()
    
