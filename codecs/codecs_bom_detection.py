#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Copyright (c) 2008 Doug Hellmann All rights reserved.
#


import codecs
from codecs_to_hex import to_hex

# Look at the raw data
with open('non-native-encoded.txt', mode='rb') as f:
    raw_bytes = f.read()

print 'Raw    :', to_hex(raw_bytes, 2)

# Re-open the file and let codecs detect the BOM
with codecs.open('non-native-encoded.txt', mode='rt', encoding='utf-16') as f:
    decoded_text = f.read()

print 'Decoded:', repr(decoded_text)
