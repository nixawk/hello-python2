#!/usr/bin/python
# -*- coding: utf-8 -*-


import requests


url = 'http://www.demo.com/index.php?id=1&name=jack'

_ = requests.utils.urlparse(url)
schema, netloc, path, params, query, fragment = _
print(netloc)

_ = requests.utils.urlunparse(_)
print(_)
