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
