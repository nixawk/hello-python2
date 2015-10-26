#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


def set_key_value(dictobj):
    dictobj['key'] = 'value'
    dictobj['KEY'] = 'VALUE'

    return dictobj


d1 = dict()
d2 = requests.utils.CaseInsensitiveDict()

print(set_key_value(d1))   # {'KEY': 'VALUE', 'key': 'value'}
print(set_key_value(d2))   # {'KEY': 'VALUE'}
