#!/usr/bin/env python
# -*- coding: utf8 -*-

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(4.0)   # Timeout after 5.0 seconds
s.connect(("search.yahoo.com", 80))
s.send("GET / HTTP/1.1\n\n")

try:
    while True:
        data = s.recv(512)

        if not data:
            break

        print data.strip()
finally:
    s.close()
