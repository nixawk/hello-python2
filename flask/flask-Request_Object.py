#!/usr/bin/python
# -*- coding: utf-8 -*-


from flask import Flask
from flask import request
from flask import render_template_string
import urllib


app = Flask(__name__)


@app.route('/login', methods=['GET', 'POST'])
def login():
    status = None

    if request.method == 'POST':
        # if request.form['username'] and request.form['password']:
        status = "POST %s" % str(request.form)
    else:
        status = 'GET %s' % urllib.urlencode(request.args)

    return render_template_string("Login status: {{ status }}", status=status)


if __name__ == '__main__':
    app.run()


"""
What happens if the key does not exist in the form attribute ? In that case a special [KeyError]
is raised. You can catch it like a standard [KeyError] but if you don't do that, a HTTP 400 Bad
Request error page is shown instead. So for many situations you don't have to deal with that problem.

To access parameters submitted in the URL (?key=value) you can use the args attribute.

    searchword = request.args.get('key', '')
"""