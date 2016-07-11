#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
import os
from urlparse import urlparse


def download(url):
    """iter_content downloads a file"""
    chunk_size = 1024

    r = requests.get(url, stream=True)

    if r and r.status_code == 200:
        downloaded_size = 0
        filename = os.path.basename(urlparse(url).path)
        print("[+] Download File: %s" % filename)

        with open(filename, 'wb') as fd:
            for chunk in r.iter_content(chunk_size):
                fd.write(chunk)
                downloaded_size += len(chunk)
                print "[+] Downloaded Size: %d" % downloaded_size

if __name__ == '__main__':
    url = ('https://pypi.python.org/packages/source/t/threadpool/'
           'threadpool-1.3.1.zip')
    download(url)
