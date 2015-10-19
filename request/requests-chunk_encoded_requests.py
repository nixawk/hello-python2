#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


def gen():
    yield 'hi'
    yield 'there'
    for i in range(1, 20, 1):
        yield str(i)

r = requests.post('http://httpbin.org/post', data=gen())
print(r.content)
