#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
from requests.auth import HTTPBasicAuth


r = requests.get('https://api.github.com/user',
                 auth=HTTPBasicAuth('user', 'pass'))
print(r.status_code)

# In fact, HTTP Basic Auth is so common that Requests provides a
# handy shorthand for using it.

r = requests.get('https://api.github.com/user', auth=('user', 'pass'))
print(r.status_code)

# If no authentication method is given with the auth argument,
# Requests will attempt to get the authentication credentials for the
# URL's hostname from the user's netrc file.
# If credentials for the hostname are found, the request is sent with
# HTTP Basic Auth.
