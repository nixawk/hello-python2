#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


r = requests.get('http://github.com', timeout=0.001)
print(r.text)

"""
timeout is not a time limit on the entire response download; rather, an
exception is raised if the server has not issued a response for timeout
seconds (more precisely, if no bytes have been received on the underlying
socket for timeout seconds)
"""

"""
The timeout value will be applied to both the connect and the read
timeouts. Specify a tupleif would like to set the values
separately:
"""

r = requests.get('https://github.com', timeout=(3.05, 27))
print(r.text)

"""
If the remote server is very slow, you can tell Resquests to wait
forever for a response, by passing None as a timeout value and then
retrieving a cup of coffee.
"""

r = requests.get('https://github.com', timeout=None)
