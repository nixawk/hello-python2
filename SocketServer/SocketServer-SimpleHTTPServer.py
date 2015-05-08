#!/usr/bin/env python
# -*- coding: utf8 -*-

import logging
import SocketServer
import SimpleHTTPServer

logging.basicConfig(level=logging.DEBUG,
                    format='%(name)s - %(message)s')


class HttpRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        self.logger = logging.getLogger('HttpRequestHanler')
        SimpleHTTPServer.SimpleHTTPRequestHandler.__init__(
            self, request, client_address, server)

    def do_GET(self):
        if self.path == "/admin":
            self.request.send("From %s:%s\n" % self.client_address)
            self.request.send("\n%s\n" % self.headers)
            return

        else:
            self.logger.debug('receive a get request')
            return SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)


if __name__ == '__main__':
    try:
        addr = ('127.0.0.1', 8080)
        s = SocketServer.TCPServer(addr, HttpRequestHandler)
        s.allow_reuse_address = True
        s.serve_forever()

        while True:
            pass

    finally:
        s.close()
