#!/usr/bin/env python
# -*- coding: utf8 -*-

import pickle
from SimpleXMLRPCServer import SimpleXMLRPCServer


def add(px, py):
    x = pickle.loads(px)
    y = pickle.loads(py)
    return pickle.dumps(x+y)

serv = SimpleXMLRPCServer(("127.0.0.1", 8090))
serv.register_function(add)
serv.serve_forever()
