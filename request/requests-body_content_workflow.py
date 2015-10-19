#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
By default, when you make a request, the body of the response is
downloaded immediately. You can override this behaviour and defer
downloading the response body until you access the
Response.content attribute with the stream parameter:"""

import requests
from contextlib import closing


url = ('https://pypi.python.org/packages/source/t/threadpool/'
       'threadpool-1.3.1.zip')

r = requests.get(url, stream=True)
for chunk in r.iter_content(1024):
    pass
print(r.headers['content-length'])
r.close()

"""
If you set stream to True when making a request, Requests cannot
release the connection back to the pool unless you cnosume all the
data or call Response.close. This can lead to inefficiency with
connections. If you find yourself partially reading request bodies (or
not reading them at all) while using stream=True, you should
consider using contextlib.closing, like this:
"""

with closing(requests.get('http://httpbin.org/get', stream=True)) as r:
    print(r.headers)
