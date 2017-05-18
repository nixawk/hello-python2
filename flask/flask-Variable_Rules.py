#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
To add variable parts to a URL you can mark these special sections as <variable_name>.
Such as part is then passed as a keyword argument to your function. Optionally a converter can
be used by specifying a rule with <converter:variable_name>.
"""

from flask import Flask


app = Flask(__name__)


@app.route('/user/<string:username>')
def show_user_profile(username):
    # show the user profile for that user
    return "User %s" % username


@app.route('/integer/<int:pageid>')
def integer(pageid):
    # show the post with the given id, the id is an integer
    return 'integer %d' % pageid


@app.route('/float/<float:pageid>')
def float(pageid):
    return 'float id: %f' % pageid


@app.route('/path/<path:urlpath>')
def path(urlpath):
    return 'path: %s' % urlpath



if __name__ == '__main__':
    app.run()


"""
The following converters exist:

string - accepts any text without a slash (the default)
int    - accepts integers
float  - like int but for floating point values
path   - like the default but also accept slashes
any    - matches one of the items povided
uuid   - accept UUID strings
"""