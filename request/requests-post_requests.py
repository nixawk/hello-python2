#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


payload = {'key1': 'value1', 'key2': 'value2'}
r = requests.post("http://httpbin.org/post", data=payload)
print(r.text)

"""
There are many times that you want to send data that is not
form-encoded. If you pass in a string instead of a dict, that data
will be posted directly.

For example, the GitHub APIv3 accepts JSON Encoded POST/PATCH data:

    >>> import json
    >>> url = 'https://api.github.com/some/endpoint'
    >>> payload = {'some': 'data'}
    >>> r = requests.post(url, data=json.dumps(payload))

Instead of encoding the dict yourself, you can also pass it directly
using the json parameter (added in version 2.4.2) and it will be
encoded automatically:

    >>> import json
    >>> url = 'https://api.github.com/some/endpoint'
    >>> payload = {'some': 'data'}
    >>> r = requests.post(url, json=payload)

"""
