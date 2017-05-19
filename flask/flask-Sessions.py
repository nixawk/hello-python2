#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
## Sessions

In addition to the request object there is also a second object called session which
allows you to store information specific to a user from one request to the next. This
is implemented on top of cookies for you and signs the cookies cryptographically.
What this means is that the user could look at the contents of your cookie but not
modify it, unless they know the secret key used for signing.

In order to use sessions you have to set a secret key.

"""

from flask import Flask
from flask import session
from flask import redirect
from flask import url_for
from flask import escape
from flask import request


app = Flask(__name__)
app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'

"""
## How to generate good secret keys


The problem with random is that it’s hard to judge what is truly random.
And a secret key should be as random as possible. Your operating system
has ways to generate pretty random stuff based on a cryptographic random
generator which can be used to get such a key:

>>> import os
>>> os.urandom(24)
'\xfd{H\xe5<\x95\xf9\xe3\x96.5\xd1\x01O<!\xd5\xa2\xa0\x9fR"\xa1\xa8'

Just take that thing and copy/paste it into your code and you're done.

"""

@app.route('/')
def index():

    if 'username' in session:
        return 'Logged in as %s' % escape(session['username'])
    return 'You are not logged in'


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session['username'] = request.form['username']
        return redirect(url_for('index'))

    return '''
        <form method="post">
            <p><input type="text" name="username">
            <p><input type="submit" value="Login">
        </form>
    '''

@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run()
