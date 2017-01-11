#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Copyright (c) 2008 Doug Hellmann All rights reserved.
#


import sys

try:
    sys.exit(1)
except SystemExit, err:
    print 'Tried to exit with code', err.code
