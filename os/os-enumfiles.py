#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
from optparse import OptionParser


def getfilepath(path):
    for dirpath, dirnames, filenames in os.walk(path):
        for filename in filenames:
            payload = "%s/%s" % (dirpath, filename)
            yield payload.replace(path, "/")


def getfilelist(path, extension=None, exclude=False):
    if not os.path.isdir(path):
        sys.stdout.write("please set a directory path.")
    else:
        # right directory path
        # no extension
        if extension is None:
            # no extension and no exclude
            if exclude is False:
                for filepath in getfilepath(path):
                    sys.stdout.write(filepath + '\n')
            # no extension and exclude
            else:
                sys.stdout.write('Please set exclude option with extension.\n')
        # with extension
        else:
            # with extension and no exclude
            if exclude is False:
                for filepath in getfilepath(path):
                    fileext = filepath.split('.')[-1]
                    if extension.upper() == fileext.upper():
                        sys.stdout.write(filepath + '\n')
            # with extension and with exclude
            else:
                for filepath in getfilepath(path):
                    fileext = filepath.split('.')[-1]
                    if extension.upper() != fileext.upper():
                        sys.stdout.write(filepath + '\n')


def main():
    parser = OptionParser()
    parser.add_option('-p',
                      '--path',
                      metavar='PATH',
                      help='set path for file list',
                      dest="path")
    parser.add_option('-e',
                      '--ext',
                      metavar='EXTENSION',
                      help='set extension for filter',
                      dest='ext')
    parser.add_option('-n',
                      '--exclude',
                      metavar='EXCLUDE',
                      help='exclude the extension set by -e',
                      dest='exclude',
                      action='store_true',
                      default=False)
    options, args = parser.parse_args()

    if not options.path:
        parser.error('select -h for help')
    else:
        getfilelist(options.path, options.ext, options.exclude)

if __name__ == '__main__':
    main()
