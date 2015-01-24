#!/usr/bin/env python
# -*- encoding: utf-8 -*-


import urlparse


def urlsplit(url):
    return urlparse.urlsplit(url)


def urlunsplit(u):
    return urlparse.urlunsplit(u)


o = urlsplit("http://www.demo.com/index.php?id=1")
print o

print urlunsplit(o)
