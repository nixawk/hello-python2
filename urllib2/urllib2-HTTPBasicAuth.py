#!/usr/bin/env python

import urllib2
import base64


def basic(url, username, password):
    request = urllib2.Request(url)
    b64str = base64.b64encode(
        '%s:%s' % (username, password)).replace('\n', '')
    request.add_header("Authorization", "Basic %s" % b64str)
    result = urllib2.urlopen(request)

    return result
