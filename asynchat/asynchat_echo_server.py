#!/usr/bin/env python
# -*- coding: utf8 -*-

import asyncore
# import socket

from asynchat_echo_handler import EchoHandler


class EchoServer(asyncore.dispatcher):
    """Receives connections and establishes handlers for each client.
    """

    def __init__(self, address):
        asyncore.dispatcher.__init__(self)

        self.create_socket(asyncore.socket.AF_INET,
                           asyncore.socket.SOCK_STREAM)
        self.bind(address)
        self.address = self.socket.getsockname()
        self.listen(1)

        return

    def handle_accept(self):
        # Called when a client connects to our socket
        client, address = self.accept()
        EchoHandler(sock=client)

        # We only want to deal with one client at a time,
        # so close as soon as we set up the handler.
        # Normally you would not do this and the server
        # would run forever or until it received instructions
        # to stop

        self.handle_close()
        return

    def handle_close(self):
        self.close()
