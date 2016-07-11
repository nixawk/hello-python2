#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


def print_url(r, *args, **kwargs):
    print(r.url)


hooks = dict(response=print_url)
r = requests.get('http://httpbin.org', hooks=dict(reponse=print_url))
print(r.status_code)
