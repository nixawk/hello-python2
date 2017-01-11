#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Copyright (c) 2008 Doug Hellmann All rights reserved.
#


try:
    print eval('five times three')
except SyntaxError, err:
    print 'Syntax error %s (%s-%s): %s' % \
        (err.filename, err.lineno, err.offset, err.text)
    print err
