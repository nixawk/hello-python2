#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


url = 'http://demo.com/abc%22%20def'
print(requests.utils.unquote(url))

url = 'http://demo.com/abc+def'
print(requests.utils.quote(url))
