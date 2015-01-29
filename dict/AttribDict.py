#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2006-2015 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import copy
import types


class AttribDict(dict):
    """
    >>> foo = AttribDict()
    >>> foo.bar = 1
    >>> foo.bar
    1
    """

    def __init__(self, dictitem=None, attribute=None):
        if dictitem is None:
            dictitem = {}

        self.attr = attribute
        dict.__init__(self, dictitem)
        self.__initialised = True

    def __getattr__(self, item):
        try:
            return self.__getitem__(item)
        except KeyError:
            raise Exception("unable to access item '%s'" % item)

    def __setattr__(self, item, value):
        if "_AttribDict__initialised" not in self.__dict__:
            return dict.__setattr__(self, item, value)

        elif item in self.__dict__:
            dict.__setattr__(self, item, value)

        else:
            self.__setitem__(item, value)

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, dict):
        self.__dict__ = dict

    def __deepcopy__(self, memo):
        retVal = self.__class__()
        memo[id(self)] = retVal

        for attr in dir(self):
            if not attr.startswith('_'):
                value = getattr(self, attr)
                if not isinstance(value,
                                  (types.BuiltinFunctionType,
                                   types.FunctionType, types.MethodType)):
                    setattr(retVal, attr, copy.deepcopy(value, memo))

        for key, value in self.items():
            retVal.__setitem__(key, copy.deepcopy(value, memo))
