#!/usr/bin/python
# -*- coding: utf-8 -*-

import base64
import binascii


"""
Results as follow:

('base64.b16encode', '5468697320697320612064656D6F20737472696E672E')
('base64.b16decode', 'This is a demo string.')
('binascii.unhexlify', 'This is a demo string.')
"""

aStr = 'This is a demo string.'
aStr_b16 = base64.b16encode(aStr)

print('base64.b16encode', aStr_b16)
print('base64.b16decode', base64.b16decode(aStr_b16))
print('binascii.unhexlify', binascii.unhexlify(aStr_b16))
