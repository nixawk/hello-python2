#!/usr/bin/env python
# -*- encoding: utf-8 -*-


import sys

reload(sys)
sys.setdefaultencoding('utf-8')

# If encoding is not 'utf-8', and AssertionError will be here.
assert sys.getdefaultencoding() == 'utf-8'
