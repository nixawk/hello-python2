#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
## Jinja Setup

Unless customized, Jinja2 is configured by Flask as follow:

- autoescaping is enabled for all templates ending in (.html, .htm, .xml) as well as .xhtml
  when using render_template()

- autoescaping is enabled for all strings when using render_template_string().

- a template has the ability to opt in/out autoescaping with the {% autoescape %} tag.

- Flask inserts a couple of global functions and helpers into the Jinja2 context,
  additionally to the values that are present by default.

"""

from flask import Flask
from flask import render_template_string


app = Flask(__name__)


@app.route('/')
def index():
	return render_template_string("<script>alert(123456)</script>")


if __name__ == '__main__':
	app.run()