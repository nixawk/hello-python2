#!/usr/bin/env python
# -*- coding: utf8 -*-

import pickle
import xmlrpclib


serv = xmlrpclib.ServerProxy('http://127.0.0.1:8090')
a = [1, 2, 3]
b = [4, 5]

r = serv.add(pickle.dumps(a), pickle.dumps(b))
c = pickle.loads(r)
print c
