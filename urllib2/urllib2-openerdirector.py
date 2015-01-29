#!/usr/bin/env python
# -*- coding: utf-8 -*-

import urllib2


handler = urllib2.HTTPHandler(debuglevel=1)
opener = urllib2.OpenerDirector()
opener.add_handler(handler)

resp = opener.open('http://www.baidu.com/')
print resp.read()
