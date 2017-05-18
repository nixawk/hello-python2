#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
URL Building

If it can match URLs, can Flask also generate them? Of course it can.
To build a URL to a specific function you can use the url_for() function.
It accepts the name of the function as first argument and a number of keyword arguments,
each corresponding to the variable part of the URL rule. Unknown variable
parts are appended to the URL as query parameters.
"""

from flask import Flask
from flask import url_for


app = Flask(__name__)


@app.route('/')
def index(): pass


@app.route('/login')
def login(): pass


@app.route('/user/<username>')
def profile(username): pass


if __name__ == '__main__':
    with app.test_request_context():
        print(url_for('index'))
        print(url_for('login'))
        print(url_for('login', next='/'))
        print(url_for('profile', username='Smith Bob'))


"""
(This also uses the test_request_context() method, explained below. It tells Flask to behave as though it is handling a request, even though we are interacting with it through a Python shell. Have a look at the explanation below. Context Locals).

Why would you want to build URLs using the URL reversing function url_for() instead of hard-coding them into your templates? There are three good reasons for this:

1. Reversing is often more descriptive than hard-coding the URLs. More importantly, it allows you to change URLs in one go, without having to remember to change URLs all over the place.
2. URL building will handle escaping of special characters and Unicode data transparently for you, so you don’t have to deal with them.
3. If your application is placed outside the URL root - say, in /myapplication instead of / - url_for() will handle that properly for you.
"""