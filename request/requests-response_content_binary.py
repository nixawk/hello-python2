#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


r = requests.get('https://api.github.com/events')
print(r.content)

# gzip and deflate trabsfer-encodings are automatically decoded for you.
"""
from PIL import Image
from StringIO import StringIO
i = Image.open(StringIO(r.content))
"""
