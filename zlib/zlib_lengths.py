#!/usr/bin/python
# -*- coding: utf-8 -*-

import zlib


original_data = 'This is the original text.'
fmt = '%15s  %15s'
print(fmt % ('len(data)', 'len(compressed)'))
print(fmt % ('-' * 15, '-' * 15))

for i in xrange(20):
    data = original_data * i
    compressed = zlib.compress(data)
    print fmt % (len(data), len(compressed)), '*' if len(data) < len(compressed) else ''
