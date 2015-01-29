#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
ProxyHandler, UnknownHandler, HTTPHandler,
HTTPDefaultErrorHandler, HTTPRedirectHandler,
FTPHandler, FileHandler, HTTPErrorProcessor
"""

import urllib2

debug_handler = urllib2.HTTPHandler(debuglevel=1)
proxy_handler = urllib2.ProxyHandler({'http': 'http://127.0.0.1:8080'})

opener = urllib2.build_opener(debug_handler, proxy_handler)
httpreq = opener.open('http://www.baidu.com/')
print httpreq.read()
