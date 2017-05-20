#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
## Standard Filters

tojson()

    This function converts the given object into JSON representation. This is for
    example very helpful if you try to generate JavaScript on the fly.

    Note that inside script tags no escaping must take place, so make sure to disable
    escaping with |safe before Flask if you intend to use it inside script tags.
"""

from flask import Flask
from flask import render_template_string


app = Flask(__name__)


@app.route('/')
def index():
    return "GET /login/username HTTP/1.0"


@app.route('/login/')
@app.route('/login/<string:username>/')
def login(username):
    # http://127.0.0.1:5000/%22);alert(123);document.write(%22
    template = """
    <script type='text/javascript'>
        document.write("{{username|tojson|safe}}");
    </script>
    """
    return render_template_string(template, username=username)


@app.errorhandler(500)
def internal_server_error(error):
    return render_template_string("Error: {{ error }}", error=str(error))


if __name__ == '__main__':
    app.run()
