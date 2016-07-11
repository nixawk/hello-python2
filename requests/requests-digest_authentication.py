#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
from requests.auth import HTTPDigestAuth

url = 'http://httpbin.org/digest-auth/auth/user/pass'
r = requests.get(url, auth=HTTPDigestAuth('user', 'pass'))
print(r.status_code)
