#!/usr/bin/env python
# -*- coding: utf8 -*-

from BaseHTTPServer import HTTPServer
from CGIHTTPServer import CGIHTTPRequestHandler
import os


os.chdir('/tmp')
serv = HTTPServer(("127.0.0.1", 8080), CGIHTTPRequestHandler)
serv.serve_forever()
