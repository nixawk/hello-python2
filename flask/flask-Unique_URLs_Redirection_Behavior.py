#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Unique URLs / Redirection Behavior

Though they look rather similar, they differ in their use of the trailing slash in the URL definition. In the first case, the canonical URL for the projects endpoint has a trailing slash. In that sense, it is similar to a folder on a filesystem. Accessing it without a trailing slash will cause Flask to redirect to the canonical URL with the trailing slash.

In the second case, however, the URL is defined without a trailing slash, rather like the pathname of a file on UNIX-like systems. Accessing the URL with a trailing slash will produce a 404 “Not Found” error.

This behavior allows relative URLs to continue working even if the trailing slash is omitted, consistent with how Apache and other servers work. Also, the URLs will stay unique, which helps search engines avoid indexing the same page twice.
"""

from flask import Flask


app = Flask(__name__)


@app.route('/projects/')
def projects():
    return 'The project page'


@app.route('/about')
def about():
    return 'The about page'


if __name__ == '__main__':
    app.run()