#!/usr/bin/env python
# -*- coding: utf8 -*-

import socket
import threading


class server(object):
    """run a multi-threaded server"""
    def __init__(self, host, port):
        self.addr = (host, port)

    def handle_client(self, client, client_addr):

        try:
            while True:
                data = client.recv(1024)
                print "[*] data from %s:%s" % client_addr

                if not data:
                    break

                client.sendall(data)

        finally:
            print "[*] close thread tcp/%d" % client_addr[1]
            client.close()

    def daemon(self):
        """server daemon"""
        self.sock = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(self.addr)
        self.sock.listen(1)

        while True:
            client, client_addr = self.sock.accept()
            t = threading.Thread(target=self.handle_client,
                                 args=(client, client_addr))

            print "[*] start a new thread with %s:%s" % client_addr
            t.start()


if __name__ == "__main__":
    server("127.0.0.1", 8080).daemon()
