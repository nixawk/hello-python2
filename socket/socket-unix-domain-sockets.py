#!/usr/bin/env python
# -*- coding: utf8 -*-

import socket

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)  # tcp
# s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)  # udp

# unix socket server
s.bind("/tmp/foo")
s.listen(5)
cli, addr = s.accept()
print cli.recv(512)

s.close()


# unix socket client
# c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)  # tcp
# c.connect("/tmp/foo")

# c.close()
