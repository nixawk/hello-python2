#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import urllib2

headers = {'User-Agent': 'Mozilla/5.0'}
req = urllib2.Request('http://www.baidu.com/', None, headers)
resp = urllib2.urlopen(req)

print resp.read()
