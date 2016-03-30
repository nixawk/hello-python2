#!/usr/bin/python
# -*- coding: utf8 -*-

import zipfile


def readfile(zip_file):
    ret = {}
    zip = zipfile.ZipFile(zip_file)

    for filename in zip.namelist():
        ret[filename] = zip.open(filename)
    return ret


def fetch_one(zip_file, filename):
    ret = readfile(zip_file)
    return ret.get(filename, None)


if __name__ == "__main__":
    f = fetch_one('/tmp/h.zip', 'test.txt')
    if f:
        for line in f: print(line.strip())
