#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
import contextlib


with contextlib.closing(requests.get('http://httpbin.org', stream=True)) as s:
    print(s.text)
