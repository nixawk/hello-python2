#!/usr/bin/env python
# -*- encoding: utf-8 -*-

"""
 urllib2.urlopen(url[,
                 data[,
                 timeout[, cafile[, capath[, cadefault[, context]]]]])

     Open the URL url, which can be either a string or a Request object.

     data should be a buffer
     in the standard application/x-www-form-urlencoded format
"""

import urllib2


def url():
    response = urllib2.urlopen('http://www.baidu.com/ee')

    redirect_url = response.geturl()
    print "Rediect to %s" % redirect_url

    return response


def request():
    req = urllib2.Request(url='http://www.baidu.com/ee')
    response = urllib2.urlopen(req)

    redirect_url = response.geturl()
    print "Rediect to %s" % redirect_url

    return response


from pprint import pprint

resp1 = url()
pprint(dir(resp1))

resp2 = request()
pprint(dir(resp2))
