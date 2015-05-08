#!/usr/bin/env python
# -*- coding: utf8 -*-

import SocketServer


class EchoRequestHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        # Echo the back to the client
        while True:
            data = self.request.recv(1024)

            if data:
                self.request.send(data)
            else:
                print "close socket"
                break
        return

if __name__ == '__main__':
    import threading

    address = ('localhost', 0)   # let the kernel give us a port
    server = SocketServer.TCPServer(address, EchoRequestHandler)
    ip, port = server.server_address  # find out what port we were given

    t = threading.Thread(target=server.serve_forever)
    t.setDaemon(True)   # don't hang on exit
    t.start()

    while True:
        pass

    # Clean up
    server.socket.close()
