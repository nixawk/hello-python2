#!/usr/bin/env python
# -*- coding: utf8 -*-

import urllib
import urllib2

query_args = {'q': 'query string', 'foo': 'bar'}

request = urllib2.Request('http://localhost:8080/')
print 'Request method before data:', request.get_method()

request.add_data(urllib.urlencode(query_args))
print 'Request method after data :', request.get_method()
request.add_header('User-Agent', 'PyMOTW (http://pymotw.com)')

print 'OUTGOING DATA:'
print request.get_data()

print 'SERVER RESPONSE'
print urllib2.urlopen(request).read()
