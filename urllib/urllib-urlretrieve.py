#!/usr/bin/env python
# -*- coding: utf8 -*-

"""
lab:urllib/ $  python2 urllib-urlretrieve.py
20% |###################                                                |
"""

import urllib
from progressbar import ProgressBar


def progress(nblocks, block_size, file_size):
    # print (nblocks*block_size*100)/float(file_size)
    if pbar.maxval is None:
        pbar.maxval = file_size
        pbar.start()

    pbar.update(min(nblocks*block_size, file_size))


if __name__ == "__main__":
    url = "https://www.python.org/ftp/python/2.7.9/Python-2.7.9.tgz"
    local_file = "Python-2.7.9.tgz"

    pbar = ProgressBar()
    urllib.urlretrieve(url, local_file, progress)
    pbar.finish()
