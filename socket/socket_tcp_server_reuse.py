#!/usr/bin/env python
# -*- coding: utf8 -*-

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9000))
s.listen(5)

while True:
    c, a = s.accept()
    print "Received connection from %s:%s" % a
    c.send("Hello %s\n" % a[0])
    c.close()
