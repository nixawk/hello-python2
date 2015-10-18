#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


url = 'https://api.github.com/users/rapid7'
headers = {'user-agent': 'my-app/0.0.1'}

r = requests.get(url, headers=headers)
print(r.json())

"""
Note: Custom headers are given less precedence than more
specific sources of information.  For instance:

    * Authorization headers will be overridden if credentials are passed via
      the auth parameter or are specified in a .netrc accessible in the
      environment.

    * Authorization headers will be removed if you get redirected off-host.

    * Proxy-Authorization headers will be overridden by proxy credentials
      provided in the URL.

    * Content-Length headers will be overridden when we can determine
      the length of the content.

Furthermore, Requests does not change its behavior at all based on
which custom headers are specified. The headers are simply passed
on into the final request.
"""
