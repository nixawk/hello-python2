#!/usr/bin/env python
# -*- coding: utf8 -*-

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

msg = "Hello World"
s.sendto(msg, ("127.0.0.1", 10000))

data, addr = s.recvfrom(1024)

print data
