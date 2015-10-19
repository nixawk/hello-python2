#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


def filepost(url, files):
    r = requests.post(url, files=files)
    print(r.text)


url = 'http://httpbin.org/post'

# Requests makes it simple to upload Multipart-encoded files
files = {'file': open('/tmp/report.xls', 'rb')}
filepost(url, files)

# set the filename, content_type and headers explicitly
files = {'file': ('report.xls', open('/tmp/report.xls', 'rb'),
                  'application/vnd.ms-excel', {'Expires': '0'})}
filepost(url, files)

# send strings to be received as files
files = {'file': ('report.csv', 'some,data,to,send\nanother,row,to,send\n')}
filepost(url, files)


"""
In the event you are posting a very large files as a multipart/form-data
request, you may want to stream the request. By default, requests does
not support this, but there is a separate package which does - requests-
toolbelt. You should read [the toolbelt's
documentation](https://toolbelt.readthedocs.org/) for more details about
how to use it.
"""
