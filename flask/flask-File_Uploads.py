#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Uploaded files are stored in memory or at a temporary location on the filesystem.
You can access those files by looking at the files attribute on the request object.
Each uploaded file is stored in that dictionary. It behaves just like a standard
Python file object, but it also has a save() method that allows you to store that
file on the filesystem of the server. Here is a simple example showing how that works:
"""

from flask import Flask
from flask import request
from werkzeug.utils import secure_filename


app = Flask(__name__)


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
	# curl -F "filename=@/tmp/abc.txt" http://127.0.0.1:5000/upload
    if request.method == 'POST':
        f = request.files['filename']
        f.save('/tmp/' + secure_filename(f.filename))

"""
If you want to know how the file was named on the client before it was uploaded to your application,
you can access the filename attribute. However please keep in mind that this value can be forged so
never ever trust that value. If you want to use the filename of the client to store the file on the
server, pass it through the secure_filename() function that Werkzeug provides for you:
"""


if __name__ == '__main__':
	app.run()