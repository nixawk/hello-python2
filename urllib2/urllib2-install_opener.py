#!/usr/bin/env python
# -*- coding: utf-8 -*-

import urllib2

handler = urllib2.HTTPHandler(debuglevel=1)
opener = urllib2.build_opener(handler)
opener.addheaders = [('User-agent', 'Mozilla/5.0')]
urllib2.install_opener(opener)

httpreq = opener.open('http://www.baidu.com/')
response = httpreq.read()
print dir(response)

import pdb
pdb.set_trace()
