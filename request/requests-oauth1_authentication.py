#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
from requests_oauthlib import OAuth1


url = 'https://api.twitter.com/1.1/account/verify_credentials.json'
auth = OAuth1('APP_KEY', 'APP_SECRET',
              'USER_OAUTH_TOKEN', 'USER_OAUTH_TOKEN_SECRET')
r = requests.get(url, auth=auth)
print(r.text)
