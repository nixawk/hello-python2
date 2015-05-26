#!/usr/bin/env python
# -*- coding: utf8 -*-

import urllib2

response = urllib2.urlopen('http://localhost:8080/')

for line in response:
    print line.rstrip()
