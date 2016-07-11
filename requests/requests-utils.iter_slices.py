#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


content = "1234567890abcdefghijklmnopqrstuvwxyz"
length = 10
for s in requests.utils.iter_slices(content, length):
    print(s)

"""
1234567890
abcdefghij
klmnopqrst
uvwxyz
"""
