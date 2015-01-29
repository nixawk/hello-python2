#!/usr/bin/env python
# -*- coding: utf-8 -*-

import urlparse

url = 'http://www.demo.com/index.html#fragment'
print urlparse.urldefrag(url)

# Result: ('http://www.baidu.com/index.html', 'fragment')
