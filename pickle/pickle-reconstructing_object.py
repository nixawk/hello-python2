#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys


try:
    import cPickle as pickle
except ImportError:
    import pickle


class SimpleObject(object):
    def __init__(self, name):
        self.name = name
        l = list(name)
        l.reverse()
        self.name_backwards = ''.join(l)

        return


if __name__ == '__main__':
    data = []
    data.append(SimpleObject('pickle'))
    data.append(SimpleObject('cPickle'))
    data.append(SimpleObject('last'))

    try:
        filename = sys.argv[1]
    except IndexError:
        raise RuntimeError(
            'Please specify a filename as an argument to %s' % sys.argv[0])

    out_s = open(filename, 'wb')

    try:
        # Write to the stream
        for o in data:
            print 'WRITING: %s (%s)' % (o.name, o.name_backwards)
            pickle.dump(o, out_s)
    finally:
        out_s.close()
