#!/usr/bin/python
# -*- coding: utf-8 -*-


import requests


url = "http://user:pass@demo.com/index.php?id=1&p=x"
print(url)
print(requests.utils.urldefragauth(url))
