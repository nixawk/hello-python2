#!/usr/bin/env python
# -*- coding: utf-8 -*-

import urlparse


def urljoin(base, url):
    return urlparse.urljoin(base, url)

print urljoin('file://home/someone/code/', '/helloworld/code')
print urljoin('http://demo.com', '/index.php')
