#!/usr/bin/python
# -*- coding: utf-8 -*-

import getpass
import sys


if sys.stdin.isatty():
    p = getpass.getpass('Using getpass:')
else:
    print('Using readline')
    p = sys.stdin.readline().rstrip()

print('Read: {}'.format(p))
