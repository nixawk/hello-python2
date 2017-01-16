#!/usr/bin/python
# -*- coding: utf-8 -*-

import uuid


# Because of the time component,
# each time uuid1() is called a new value is returned.
for i in xrange(3):
    print uuid.uuid1()
