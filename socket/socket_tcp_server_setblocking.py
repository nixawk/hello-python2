#!/usr/bin/env python
# -*- coding: utf8 -*-

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setblocking(True)  # default
s.bind(("127.0.0.1", 10000))
s.listen(5)
client, addr = s.accept()

print "%s:%s" % addr
