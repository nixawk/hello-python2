#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
import tempfile


r = requests.get('https://api.github.com/events', stream=True)
# print(r.raw)
# print(r.raw.read(10))

# Using Response.iter_content will handle a lot of what you would
# otherwise have to handle when using Response.raw directly. When
# streaming a download, the above is the preferred and recommended
# way to retrieve the content.

chunk_size = 1024

with open(tempfile.mktemp(), 'wb') as fd:
    for chunk in r.iter_content(chunk_size):
        fd.write(chunk)
