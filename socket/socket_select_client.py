#!/usr/bin/env python
# -*- coding: utf8 -*-

import socket

messages = ['This is the message',
            'It will be sent',
            'in parts']

server_address = ('localhost', 10000)

# Create a TCP/IP socket
socks = [socket.socket(socket.AF_INET,
                       socket.SOCK_STREAM,
                       socket.IPPROTO_TCP)
         for i in range(3)]

# Connect the socket to the port where the server is listening
print 'connecting to %s port %s' % server_address

for s in socks:
    s.connect(server_address)

for message in messages:

    # Send messages on both sockets
    for s in socks:
        print '%s: sending "%s"' % (s.getsockname(), message)
        s.send(message)

    # Read response on both sockets
    for s in socks:
        data = s.recv(1024)
        print '%s: received "%s"' % (s.getsockname(), data)
        if not data:
            print 'closing socket', s.getsockname()
            s.close()
