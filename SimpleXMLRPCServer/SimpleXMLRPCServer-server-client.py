#!/usr/bin/env python
# -*- coding: utf8 -*-

import xmlrpclib


s = xmlrpclib.ServerProxy("http://127.0.0.1:8090")
print s.add(1, 3)
print s.add('hello ', 'python')
