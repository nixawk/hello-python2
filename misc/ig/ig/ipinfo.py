#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


class ipinfo(object):
    def __init__(self):
        super(ipinfo, self).__init__()

    def search(self, ip):
        """Search ip details from ipinfo.io
        """
        data = {'ip': ip}
        api_url = 'https://ipinfo.io'
        resp = requests.post(api_url, data=data)
        return resp.json()


if __name__ == '__main__':
    i = ipinfo()
    ip = '8.8.8.8'
    from pprint import pprint
    pprint(i.search(ip))
