#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


r = requests.get('http://httpbin.org/get')
print(r.headers)


"""
We can view the server's response headers using a Python dictionary.
The dictionary is special, through: it's made just for HTTP headers.
According to RFC 7230, HTTP Header names are case-insensitive.

    >>> r.headers['Content-Type']
    >>> r.headers.get('content-type')
"""
