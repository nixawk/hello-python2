#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests


def make_request(method, url, headers={}, files=None, data={},
                 json=None, params={}, auth=None,
                 cookies=None, hooks={}):
    req = requests.Request(method, url, headers={},
                           files=None, data={},
                           json=None, params={},
                           auth=None,
                           cookies=None, hooks={})

    r = req.prepare()
    s = requests.Session()

    response = s.send(r)

    return response


def get_cookies_from_response(response):
    if hasattr(response, 'cookies'):
        return response.cookies

    return None


def save_cookies_to_file(url):
    pass


from pprint import pprint

response = make_request('GET', 'http://www.baidu.com/')
cookies = get_cookies_from_response(response)

pprint(dir(cookies))
