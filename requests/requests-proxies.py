#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests

proxies = {
    "http": "http://10.10.1.10:3128",
    "http": "http://user:pass@10.10.1.10:3128",
    "https": "http://10.10.1.10:1080",
}

requests.get("http://example.org", proxies=proxies)

"""
You can also configure proxies by setting the environment variables
HTTP_PROXY and HTTPS_PROXY.
"""
