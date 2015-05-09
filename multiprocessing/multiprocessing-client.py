#!/usr/bin/env python
# -*- coding: utf8 -*-

from multiprocessing.connection import Client


c = Client(("127.0.0.1", 8080), authkey="password")
print c.recv()
c.close()
