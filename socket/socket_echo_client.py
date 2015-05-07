#!/usr/bin/env python
# -*- coding: utf8 -*-

# reverse shell client (no nc shell)
#
# lab:socket/ $ python socket_echo_client.py
# [*] socket_client> id
# data back: uid=1000(lab) gid=1000(lab) groups=1000(lab)

# [*] socket_client> exit


import socket


c = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
s_addr = ('127.0.0.1', 10000)
c.connect(s_addr)

while True:
    data = raw_input('[*] socket_client> ')

    if data.strip() in ('exit', 'quit'):
        break

    elif data:
        c.send(data)
        _ = c.recv(1024)

        print _

c.close()
