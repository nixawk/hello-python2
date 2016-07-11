#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


# Make a Request
r = requests.put("http://httpbin.org/put", data={"key": "value"})
r = requests.delete("http://httpbin.org/delete")
r = requests.head("http://httpbin.org/get")
r = requests.options("http://httpbin.org/get")
