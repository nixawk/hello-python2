#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
## Rendering Templates

Generating HTML from within Python is not fun, and actually pretty cumbersome because
you have to do the HTML escaping on your own to keep the application secure. Because
of that Flask configures the Jinja2 template engine for you automatically.

To render a template you can use the render_template() method. All you have to do is
provide the name of the template and the variables you want to pass to the template
engine as keyword arguments. Here’s a simple example of how to render a template:
"""

from flask import Flask
from flask import render_template
from flask import render_template_string


app = Flask(__name__)


@app.route('/')
@app.route('/<string:name>')
def index(name=None):
    # return render_template('500.html')
    return render_template_string('hello {{ username }}', username=name)


@app.errorhandler(500)
def internal_server_error(e):
    # Flask will look for templates in the templates folder. 
    # So if your application is a module, this folder is next to that module, 
    # if it’s a package it’s actually inside your package: <wwwroot>/templates/500.html

    # Inside templates you also have access to the [request], [session], and [g] objects
    # as well as the [get_flashed_messages()] function.

    # Automatic escaping is enabled, so if name contains HTML it will be escaped automatically.
    return render_template('500.html')


if __name__ == '__main__':
    app.run()