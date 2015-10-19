#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


r = requests.get('http://httpbin.org/get')

if (r.status_code == requests.codes.ok):
    print('[+] http response is ok')

"""
If we made a bad request (a 4XX client error or 5XX server error response),
we can raise it with Response.raise_for_status():

    >>> bad_r = requests.get('http://httpbin.org/status/404')
    >>> bad_r.status_code
    404

    >>> bad_r.raise_for_status()
    Traceback (most recent call last):
      File "requests/models.py", line 832, in raise_for_status
        raise http_error
      requests.exceptions.HTTPError: 404 Client Error

But, since our status_code for r was 200, when we call
raise_for_status() we get:

    >>> r.raise_for_status()
    None

"""
