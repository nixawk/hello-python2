#!/usr/bin/env python
# -*- coding: utf8 -*-

from SimpleXMLRPCServer import SimpleXMLRPCServer


def add(x, y):
    return x + y

s = SimpleXMLRPCServer(("127.0.0.1", 8090))
s.register_function(add)
s.serve_forever()
