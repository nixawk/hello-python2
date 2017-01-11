#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Copyright (c) 2008 Doug Hellmann All rights reserved.
#


import difflib
from difflib_data import *

diff = difflib.unified_diff(text1_lines, text2_lines, lineterm='')
print '\n'.join(list(diff))
