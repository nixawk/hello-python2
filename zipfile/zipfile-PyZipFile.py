#!/usr/bin/python
# -*- coding: utf8 -*-

# https://pymotw.com/2/zipimport/index.html#module-zipimport

import sys
import zipfile


if __name__ == '__main__':
    zf = zipfile.PyZipFile('zipimport_example.zip', mode='w')
    try:
        zf.writepy('.')
        zf.write('/tmp/README.txt')
    finally:
        zf.close()
    for name in zf.namelist():
        print(name)
