#!/usr/bin/env python
# -*- coding: utf8 -*-

import urllib2


request = urllib2.Request('http://localhost:8080/')
request.add_header('User-Agent', 'PyMOTW (http://pymotw.com)')
response = urllib2.urlopen(request)
data = response.read()

print data
