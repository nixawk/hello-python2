#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


url = 'https://www.metasploit.com'
r = requests.get(url)
print(r.cookies)

# If a response contains some Cookies, you can quickly access them:
print(r.cookies['value'])

# To send your own cookies to the server, you can use the cookies parameter
url = 'http://httpbin.org/cookies'
cookies = dict(cookies_are='working')
# cookies = old_cookies.update(new_cookies)

r.requests.get(url, cookies=cookies)
print(r.cookies)
