#!/usr/bin/python
# -*- coding: utf-8 -*-

import timeit


print(timeit.repeat(
    "char in text",    # stmt
    setup="char = 'l'; text = 'hello'",
    repeat=3,
    number=10000000    # number
))
