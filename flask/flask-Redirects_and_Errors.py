#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
To redirect a user to another endpoint, use the redrect() function;
To abort a request early with an error code, use the abort() function.
"""

from flask import Flask
from flask import abort
from flask import redirect
from flask import url_for
from flask import render_template_string


app = Flask(__name__)


@app.route('/')
def index():
	return redirect(url_for('login'))


@app.route('/login/')
def login():

	# This is a ranther pointless example because a user will be redirected from the index
	# to a page they cannot access (401 means access denied) but it shows that works.

	abort(401)
	return "login successfully"


@app.errorhandler(404)
def page_not_found(e):
	return render_template_string('Error - {{ e }}', e=str(e))


if __name__ == '__main__':
	app.run()