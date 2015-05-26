#!/usr/bin/env python
# -*- coding: utf8 -*-

import urllib
import urllib2


query_args = {'q': 'query string', 'foo': 'bar'}
encoded_args = urllib.urlencode(query_args)
print 'Encoded:', encoded_args
url = 'http://localhost:8080/?%s' % encoded_args
print urllib2.urlopen(url).read()
