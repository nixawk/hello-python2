#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Message Flashing

Good applications and user interface are all about feedback. If the user does not
get enough feedback they will probably end up hating the application. Flask
provides a really simple way to give feedback to a user with the flashing system.
The flashing system basically makes it possible to record a message at the end of
a request and access it on the next (and only the next) request. This is usually
combined with a layout template to expose the message.

To flash a message use the flash() method, to get hold of the messages you can
use get_flashed_messages() which is also available in the templates. Check out
the Message Flashing for a full example.
"""

from flask import Flask
from flask import flash
from flask import render_template_string
from flask import get_flashed_messages


app = Flask(__name__)
app.secret_key = 'keysecret'   # Enable flask message


@app.route('/')
def index():
    flash("Hello Python")
    flash('Hello Flask')
    flash('Hello Message')

    return render_template_string('Messages: {{ messages }}', messages=get_flashed_messages())


if __name__ == '__main__':
    app.run(debug=True)