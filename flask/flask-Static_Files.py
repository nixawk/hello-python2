#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Static Files

Dynamic web application also need static files. That's usually where the CSS and
JavaScript files are coming from. Ideally your web server is configured to serve
them for you, but during development Flask can do that as well. Just create a folder
called static in your package or next to your module and it will be available at
/static on the application.

    url_for('static', filename='style.css')

The file has to stored on the filesystem as static/style.css.

"""

from flask import Flask
from flask import url_for


app = Flask(__name__)



if __name__ == '__main__':
    with app.test_request_context():
        print(url_for('static', filename="style.css"))