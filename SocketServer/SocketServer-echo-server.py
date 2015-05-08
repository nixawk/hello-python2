#!/usr/bin/env python
# -*- coding: utf8 -*-

import SocketServer
import logging
import threading

#
# SocketServer.BaseRequestHandler
# SocketServer.BaseServer
# SocketServer.DatagramRequestHandler
# SocketServer.ForkingMixIn
# SocketServer.ForkingTCPServer
# SocketServer.ForkingUDPServer
# SocketServer.StreamRequestHandler
# SocketServer.TCPServer
# SocketServer.ThreadingMixIn
# SocketServer.ThreadingTCPServer
# SocketServer.ThreadingUDPServer
# SocketServer.ThreadingUnixDatagramServer
# SocketServer.ThreadingUnixStreamServer
# SocketServer.UDPServer
# SocketServer.UnixDatagramServer
# SocketServer.UnixStreamServer
# SocketServer.errno
# SocketServer.os
# SocketServer.select
# SocketServer.socket
# SocketServer.sys
# SocketServer.threading


logging.basicConfig(level=logging.DEBUG,
                    format='%(name)s: %(message)s')


class EchoRequestHandler(SocketServer.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self.logger = logging.getLogger('EchoRequestHandler')
        self.logger.debug('__init__')
        SocketServer.BaseRequestHandler.__init__(self, request,
                                                 client_address, server)
        return

    def setup(self):
        self.logger.debug('setup')
        return SocketServer.BaseRequestHandler.setup(self)

    def handle(self):
        self.logger.debug('handle')

        # Echo the back to the client
        while True:
            data = self.request.recv(1024)
            self.logger.debug('recv() -> "%s"', data.strip())

            if data:
                self.request.send(data)
            else:
                break

        return

    def finsh(self):
        self.logger.debug('finish')
        return SocketServer.BaseRequestHandler.finish(self)


class EchoServer(SocketServer.TCPServer):
    def __init__(self, server_address, handler_class=EchoRequestHandler):
        self.logger = logging.getLogger('EchoServer')
        self.logger.debug('__init__')
        SocketServer.TCPServer.__init__(self, server_address, handler_class)
        return

    def server_activate(self):
        self.logger.debug('server_activate')
        SocketServer.TCPServer.server_activate(self)
        return

    def serve_forever(self):
        self.logger.debug('waiting for request')
        self.logger.info('Handling requests, press <Ctrl-C> to quit')
        while True:
            self.handle_request()
        return

    def handle_request(self):
        self.logger.debug('handle_request')
        return SocketServer.TCPServer.handle_request(self)

    def verify_request(self, request, client_address):
        self.logger.debug('verify_request(%s, %s)', request, client_address)
        return SocketServer.TCPServer.verify_request(self,
                                                     request, client_address)

    def process_request(self, request, client_address):
        self.logger.debug('process_request(%s, %s)', request, client_address)
        return SocketServer.TCPServer.process_request(self,
                                                      request, client_address)

    def server_close(self):
        self.logger.debug('server_close')
        return SocketServer.TCPServer.server_close(self)

    def finish_request(self, request, client_address):
        self.logger.debug('finish_request(%s, %s)', request, client_address)
        return SocketServer.TCPServer.finish_request(self,
                                                     request, client_address)

    def close_request(self, request_address):
        self.logger.debug('close_request(%s)', request_address)
        return SocketServer.TCPServer.close_request(self, request_address)


if __name__ == "__main__":
    # address = ('localhost', 0)    # let the kernel give us a port
    address = ('localhost', 10000)  # bind tcp port 10000
    server = EchoServer(address, EchoRequestHandler)
    ip, port = server.server_address

    t = threading.Thread(target=server.serve_forever)
    t.setDaemon(True)
    t.start()

    while True:
        pass

    server.socket.close()
