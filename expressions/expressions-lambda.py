#!/usr/bin/env python
# -*- coding: utf-8 -*-

flag = True


def get_method():
    if flag:
        return 'GET'
    else:
        return 'POST'

print get_method()
get_method = lambda: 'HEAD'
print get_method()
