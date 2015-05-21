#!/usr/bin/env python
# -*- coding: utf8 -*-

import logging
import asyncore

from asynchat_echo_server import EchoServer
from asynchat_echo_client import EchoClient

logging.basicConfig(level=logging.DEBUG,
                    format='%(name)s: %(message)s')

address = ('localhost', 0)  # let the kernel give us a port
server = EchoServer(address)
ip, port = server.address  # find out what port we were given

message_data = open('/tmp/socket.txt', 'r').read()
client = EchoClient(ip, port, message=message_data)

asyncore.loop()
