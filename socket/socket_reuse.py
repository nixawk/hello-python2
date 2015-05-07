#!/usr/bin/env python
# -*- coding: utf8 -*-

import socket

sock = socket.socket(socket.AF_INET,
                     socket.SOCK_STREAM,
                     socket.IPPROTO_TCP)

sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", 8080))
sock.listen(1)

client, client_addr = sock.accept()

print "connection from %s:%s" % client_addr

while True:
    data = client.recv(1024)

    if data:
        print data
    else:
        break

sock.close()
