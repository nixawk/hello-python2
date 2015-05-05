#!/usr/bin/env python
# -*- coding: utf8 -*-

import glob
import os
import time


def fileinfo(filename):
    """get file information (file size, modified time, create time)"""
    st_mode, st_ino, st_dev, st_nlink, \
        st_uid, st_gid, st_size, \
        st_atime, st_mtime, st_ctime = os.stat(filename)

    return "{size: %s bytes, create_time: %s, modify_time: %s}" % \
        (st_size, time.ctime(st_mtime), time.ctime(st_ctime))


def listdir(dirpath, prefix='----', dirlevel=0):
    """list files in directory"""
    if os.path.isdir(dirpath):
        items = glob.glob(os.path.join(dirpath, "*"))

        dirprefix = prefix * dirlevel
        dirlevel += 1

        for i in items:
            print "%s%s - %s" % (dirprefix,
                                 i.replace(
                                     "%s%s" % (dirpath, os.path.sep), ""
                                 ),
                                 fileinfo(i))

            if os.path.isdir(i):
                listdir(os.path.join(dirpath, i), prefix, dirlevel)

    else:
        print "not support"


if __name__ == "__main__":
    # please set a proper directory path
    listdir('/tmp')
