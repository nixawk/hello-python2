#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


r = requests.get('https://api.github.com/events')
print(r.encoding)
print(r.text)
