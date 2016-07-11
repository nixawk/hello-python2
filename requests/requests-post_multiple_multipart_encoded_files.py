#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


url = 'http://httpbin.org/post'
multiple_files = [
    ('images', ('foo.png', open('foo.png', 'rb'), 'image/png')),
    ('images', ('bar.png', open('bar.png', 'rb'), 'image/png'))]

r = requests.post(url, files=multiple_files)
print(r.text)
