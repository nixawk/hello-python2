#!/usr/bin/env python
# -*- coding: utf-8 -*-

import urllib2


class _HTTPRedirectHandler(urllib2.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        print "Cookie Manip Right Here"
        return urllib2.HTTPRedirectHandler.http_error_302(
            self, req, fp, code, msg, headers)

opener = urllib2.build_opener(_HTTPRedirectHandler)
urllib2.install_opener(opener)

resp = urllib2.urlopen('http://www.baidu.com/')
print resp.read()
