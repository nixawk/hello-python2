#!/usr/bin/env python
# -*- coding: utf8 -*-

import mechanize


request = mechanize.Request("https://github.com/")

# note we're using the urlopen from mechanize, not urllib2
response = mechanize.urlopen(request)

cj = mechanize.CookieJar()
cj.extract_cookies(response, request)

# let's say this next request requires a cookie that was set
# in response
request2 = mechanize.Request("https://github.com/explore")
response2 = mechanize.urlopen(request2)

print response2.geturl()
print response2.info()          # headers
print len(response2.read())     # body (readline and readlines work too)

# In this examples, the workings are hidden inside the mechanize.urlopen()
# function, which is an extension of urllib2.urlopen(). Redirects, proxies and
# cookies are handled automatically by this function (note that you may need a
# bit of configuration to get your proxies correctly set up: see urllib2
# documentation)
