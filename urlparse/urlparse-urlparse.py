#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import urlparse


def parseUrl(url):
    # scheme, netloc, path, params, query, fragment = urlparse.urlparse(url)
    # return netloc, path

    o = urlparse.urlparse(url)
    return o


def unparseUrl(unurl):
    """
    ParseResult(
        scheme='http',
        netloc='www.demo.com:80',
        path='/index.php',
        params='',
        query='id=123',
        fragment=''
        )
    """
    o = urlparse.urlunparse(unurl)

    return o

if __name__ == '__main__':
    url1 = 'http://www.demo.com:80/index.php?id=123'
    url2 = 'file:///home/someone/pieces/urlparse.py'
    url3 = 'ftp://demo.com:21/code'

    print url1
    print url2
    print url3

    u1 = parseUrl(url1)
    u2 = parseUrl(url2)
    u3 = parseUrl(url3)

    print u1
    print u2
    print u3

    print unparseUrl(u1)
    print unparseUrl(u2)
    print unparseUrl(u3)
