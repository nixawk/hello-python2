#!/usr/bin/python
# -*- coding: utf-8 -*-

import base64


"""
('base64.b32encode', 'KRUGS4ZANFZSAYJAMRSW23ZAON2HE2LOM4XA====')
('base64.b32decode', 'This is a demo string.')
('base64.b64decode', ')\x15\x06K\x86@4VR\x01\x82@1\x14\x96\xdbv@8\xdd\x87\x13b\xce3\x85\xc0'
"""

aStr = 'This is a demo string.'
aStr_b32 = base64.b32encode(aStr)

print('base64.b32encode', aStr_b32)
print('base64.b32decode', base64.b32decode(aStr_b32))
print('base64.b64decode', base64.b64decode(aStr_b32))
