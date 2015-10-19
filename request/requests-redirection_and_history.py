#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
By default Requests will perform location redirection for all verbs except
HEAD.

We can use the history property of the Response object to track redirection.

The Response.history list contains the Response object that were created in
order to complete the request.
"""

import requests


r = requests.get('http://github.com')   # Default:  allow_redirects=True
print(r.url)
print(r.status_code)
print(r.history)
print('')

"""
If you're using GET, OPTIONS, POST, PUT, PATCH, or DELETE, you can
disable redirection handling with the allow_redirects parameter:
"""

r = requests.get('http://github.com', allow_redirects=False)
print(r.url)
print(r.status_code)
print(r.history)
print('')

"""
If you're using HEAD, you can enable redirection as well:
"""

r = requests.head('http://github.com', allow_redirects=True)
print(r.url)
print(r.status_code)
print(r.history)
print('')
