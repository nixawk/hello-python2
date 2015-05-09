#!/usr/bin/env python
# -*- coding: utf8 -*-

from BaseHTTPServer import HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
import os


os.chdir('/tmp')
serv = HTTPServer(("127.0.0.1", 8080), SimpleHTTPRequestHandler)
serv.serve_forever()
