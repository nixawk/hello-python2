#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


with open('/tmp/demo.txt', 'rb') as f:
    r = requests.post('http://httpbin.org/post', data=f)
    print(r.content)

"""
Requests supports streaming uploads, which allow you to send large
streams or files without reading them into memory. To stream and
upload, simply provide a file-like object for your body.
"""
