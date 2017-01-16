#!/usr/bin/python
# -*- coding: utf-8 -*-


import base64

"""
('base64.b64encode', 'VGhpcyBpcyBhIGRlbW8gc3RyaW5nLg==')
('base64.b64decode', 'This is a demo string.')
"""
aStr = 'This is a demo string.'
aStr_b64 = base64.b64encode(aStr)

print('base64.b64encode', aStr_b64)
print('base64.b64decode', base64.b64decode(aStr_b64))
