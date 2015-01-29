#!/usr/bin/env python
# -*- coding: utf-8 -*-

import urllib2

opener = urllib2.build_opener(urllib2.HTTPHandler(debuglevel=1))
request = urllib2.Request('http://www.baidu.com/')
request.add_header('User-Agent', 'Mozilla/5.0')
request.get_method = lambda: 'HEAD'

url = opener.open(request)
print dir(url)
