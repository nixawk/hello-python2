#!/usr/bin/env python
# -*- coding: utf8 -*-

import socket


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)

address = ('invalid-socket-address', 8888)

# socket.connect will raise a error
try:
    sock.connect(address)
except socket.error as err:
    print err.errno

# socket.connect_ex will return a value
# If ret is 0, it's successful.
ret = sock.connect_ex(address)

if ret != 0:
    print "Error: %d" % ret
