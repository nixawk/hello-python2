#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


payload1 = {'key1': 'value1', 'key2': 'value2'}
payload2 = {'key1': 'value1', 'key2': ['value2', 'value3']}

for payload in (payload1, payload2):
    r1 = requests.get("http://httpbin.org/get", params=payload)
    r2 = requests.post("http://httpbin.org/post", data=payload)
    print(r1.url)
    print(r2.url)
