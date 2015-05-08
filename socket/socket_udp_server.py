#!/usr/bin/env python
# -*- coding: utf8 -*-

import socket

# Create a new socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind a socket
s.bind(("127.0.0.1", 10000))

while True:
    data, addr = s.recvfrom(1024)
    print data

    s.sendto(data, addr)
