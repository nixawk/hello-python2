#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import urlparse

url = 'http://www.demo.com/index.html#fragment'
print urlparse.urldefrag(url)

# Result: ('http://www.baidu.com/index.html', 'fragment')
