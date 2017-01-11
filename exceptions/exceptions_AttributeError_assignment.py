#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Copyright (c) 2008 Doug Hellmann All rights reserved.
#


class MyClass(object):

    @property
    def attribute(self):
        return 'This is the attribute value'

o = MyClass()
print o.attribute
o.attribute = 'New value'
