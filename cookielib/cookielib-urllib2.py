#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cookielib import Cookie
from cookielib import CookieJar
from cookielib import FileCookieJar
from cookielib import LWPCookieJar
import urllib2


def make_cookie(name, value, domain, path='/'):
    return Cookie(version=0,
                  name=name,
                  value=value,
                  port=None,
                  port_specified=False,
                  domain=domain,
                  domain_specified=True,
                  domain_initial_dot=False,
                  path=path,
                  path_specified=True,
                  secure=False,
                  expires=None,
                  discard=False,
                  comment=None,
                  comment_url=None,
                  rest=None,
                  rfc2109=False)


def add_cookie(cookiejar, cookie):
    if isinstance(cookiejar, CookieJar):
        cookiejar.set_cookie(cookie)


def del_cookie(cookiejar, domain, path, cookiename):
    if isinstance(cookiejar, CookieJar):
        cookiejar.clear(domain, path, cookiename)


def get_cookies_from_response(url):
    cookiejar = CookieJar()

    opener = urllib2.build_opener(
        urllib2.HTTPCookieProcessor(cookiejar))
    opener.open(url)

    # add a new cookie or replace a old one
    newcookie = make_cookie('newcookie', '11111', '.baidu.com', '/')

    # remove a cookie
    cookiejar.set_cookie(newcookie)
    cookiejar.clear('.baidu.com', '/', 'newcookie')

    return cookiejar


def save_cookies_to_file1(url):
    cookiefile = 'cookies.log'

    filecookiejar = FileCookieJar(filename=cookiefile)

    opener = urllib2.build_opener(
        urllib2.HTTPCookieProcessor(filecookiejar))
    opener.open(url)

    # *******************************************
    # please read code cookielib [FileCookieJar]

    # filecookiejar.save(filename=cookiefile)
    # raise NotImplementedError()
    # ******************************************

    try:
        filecookiejar.save()
    except NotImplementedError as e:
        print e

    return filecookiejar


def save_cookies_to_file2(url):
    cookiefile = 'cookies.log'

    lwpcookiejar = LWPCookieJar(filename=cookiefile)

    opener = urllib2.build_opener(
        urllib2.HTTPCookieProcessor(lwpcookiejar))
    opener.open(url)

    lwpcookiejar.save()

    return lwpcookiejar

from pprint import pprint
pprint(get_cookies_from_response('http://www.baidu.com'))

pprint(save_cookies_to_file1('http://www.baidu.com'))
pprint(save_cookies_to_file2('http://www.baidu.com'))
