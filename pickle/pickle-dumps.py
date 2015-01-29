#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
https://docs.python.org/2/library/pickle.html
"""

try:
    import cPickle as pickle
except ImportError:
    import pickle


def pickle_encode(data):
    return pickle.dumps(data)


def pickle_decode(data):
    return pickle.loads(data)


data = {'name': 'Jim Green', 'age': 'hoho'}
e = pickle_encode(data)
d = pickle_decode(e)

print repr(e)
print repr(d)

print 'SAME ?: ', (d is data)
print 'EQUAL?: ', (d == data)
