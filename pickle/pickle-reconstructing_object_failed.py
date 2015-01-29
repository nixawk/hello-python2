#!/usr/bin/env python
# -*- coding: utf-8 -*-

# http://pymotw.com/2/pickle/index.html#module-pickle

try:
    import cPickle as pickle
except ImportError:
    import pickle


# from pprint import pprint
import sys


try:
    filename = sys.argv[1]
except IndexError:
    raise RuntimeError(
        'Please specify a filename as an argument to %s' % sys.argv[0])

in_s = open(filename, 'rb')
try:
    # Read the data
    while True:
        try:
            o = pickle.load(in_s)
        except EOFError:
            break
        else:
            print 'READ: %s (%s)' % (o.name, o.name_backwards)
finally:
    in_s.close()
