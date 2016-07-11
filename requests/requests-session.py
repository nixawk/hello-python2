#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


s = requests.Session()
s.get('http://httpbin.org/cookies/set/sessioncookie/123456789')
r = s.get('http://httpbin.org/cookies')

print(r.text)

"""
Sessions can also be used to provide default data to the request methods.
This is done by providing data to the properties on a Session object:
"""

s = requests.Session()
s.auth = ('user', 'pass')
s.headers.update({'x-test': 'true'})

# both 'x-test' and 'x-test2' are sent
s.get('http://httpbin.org/headers', headers={'x-test2': 'true'})

# If you want to manually add cookies to your session, use the Cookie utility
# functions to manipulate Session.cookies

with requests.Session() as s:
    s.get('http://httpbin.org/cookies/set/sessioncookie/123456789')
