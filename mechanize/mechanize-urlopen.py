#!/usr/bin/env python
# -*- coding: utf8 -*-

import mechanize


# This function behaves identically to urllib2.urlopen(), except that it deals
# with cookies automatically.
response = mechanize.urlopen('https://github.com/')
print len(response.read())
