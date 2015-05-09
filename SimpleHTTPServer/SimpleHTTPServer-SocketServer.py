#!/usr/bin/env python
# -*- coding: utf8 -*-

from SimpleHTTPServer import SimpleHTTPRequestHandler
from SocketServer import TCPServer
import os


os.chdir('/tmp')
s = TCPServer(('127.0.0.1', 8080), SimpleHTTPRequestHandler)
s.serve_forever()
