#!/usr/bin/python
# -*- coding: utf-8 -*-

# sudo pip install requests requests_toolbelt

import requests
from requests_toolbelt.utils import dump


def http_raw_response(url, timeout=8):
    r = requests.get(url, timeout=timeout)
    data = dump.dump_all(r)
    data = data.decode("utf-8")

    return data


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 2:
        print("[*] python %s <url>" % sys.argv[0])
        sys.exit(0)

    url = sys.argv[1]
    data = http_raw_response(url)

    print(data)