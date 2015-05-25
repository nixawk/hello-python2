#!/usr/bin/env python
# -*- coding: utf8 -*-

import socket

# nc -v -l -p 8888
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 8888))
sock1 = sock.dup()

sock.send('Hello Python !\n')
sock1.send('Hello World !\n')

# sock1 closes, but sock is still open
sock1.close()

sock.send('Hello everybody !\n')

sock.close()
