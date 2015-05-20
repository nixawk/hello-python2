#!/usr/bin/env python
# -*- coding: utf8 -*-

import asyncore
import logging


class EchoServer(asyncore.dispatcher):
    """Receives connections and establishes handlers for each client
    """

    def __init__(self, address):
        self.logger = logging.getLogger('EchoServer')

        asyncore.dispatcher.__init__(self)

        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bind(address)
        self.address = self.socket.getsockname()
        self.logger.debug('binding to %s', self.address)
        self.listen(1)
        return

    def handle_accept(self):
        # Called when a client connects to our socket
        client, caddress = self.accept()

        self.logger.debug('handle_accept() -> %s', caddress)

        EchoHandler(sock=client)
        # We only want to deal with one client at a time,
        # so close as soon as we set up the handler.
        # Normally you would not do this and the server
        # would run forever or util it received instructions
        # to stop
        self.handle_close()
        return

    def handle_close(self):
        self.logger.debug('handle_close()')
        self.close()
        return


class EchoHandler(asyncore.dispatcher):
    """Handles echoing messages from a single client.
    """
    def __init__(self, sock, chunk_size=256):
        self.chunk_size = chunk_size
        self.logger = logging.getLogger(
            'EchoHandler%s' % str(sock.getsockname()))

        asyncore.dispatcher.__init__(self, sock=sock)

        self.data_to_write = []
        return

    def writable(self):
        response = bool(self.data_to_write)
        self.logger.debug('writable() -> %s', response)
        return response

    def handle_write(self):
        """Write as much as possible of the most recent message
        we have received"""
        data = self.data_to_write.pop()
        sent = self.send(data[:self.chunk_size])
        if sent < len(data):
            remaining = data[sent:]
            self.data.to_write.append(remaining)

        self.logger.debug('handle_write() -> (%d) "%s"', sent, data[:sent])

        if not self.writable():
            self.handle_close()

    def handle_read(self):
        """Read an incoming message from the client
        and put it into our outgoing queues"""
        data = self.recv(self.chunk_size)
        self.logger.debug('handle_read() -> (%d) - "%s"', len(data), data)
        self.data_to_write.insert(0, data)

    def handle_close(self):
        self.logger.debug('handle_close')
        self.close()


class EchoClient(asyncore.dispatcher):
    """Send messages to the server and receives responses."""

    def __init__(self, host, port, message, chunk_size=512):
        self.message = message
        self.to_send = message
        self.received_data = []
        self.chunk_size = chunk_size
        self.logger = logging.getLogger('EchoClient')
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger.debug('connecting to %s', (host, port))
        self.connect((host, port))
        return

    def handle_connect(self):
        self.logger.debug('handle_connect()')

    def handle_close(self):
        self.logger.debug('handle_close()')
        self.close()

        received_message = ''.join(self.received_data)
        if received_message == self.message:
            self.logger.debug('RECEIVED COPY OF MESSAGE')
        else:
            self.logger.debug('ERROR IN TRANSMISSION')
            self.logger.debug('EXPECTED "%s"', self.message)
            self.logger.debug('RECEIVED "%s"', received_message)
        return

    def writable(self):
        self.logger.debug('writable() -> "%s"', bool(self.to_send))
        return bool(self.to_send)

    def handle_write(self):
        sent = self.send(self.to_send[:self.chunk_size])
        self.logger.debug('handle_write() -> (%d) "%s"',
                          sent, self.to_send[:sent])
        self.to_send = self.to_send[sent:]

    def handle_read(self):
        data = self.recv(self.chunk_size)
        self.logger.debug('handle_read() -> (%d) "%s"', len(data), data)
        self.received_data.append(data)

if __name__ == '__main__':
    import socket

    logging.basicConfig(level=logging.DEBUG,
                        format='%(name)s: %(message)s')

    address = ('localhost', 0)    # let the kernel give us a port
    server = EchoServer(address)
    ip, port = server.address     # find out what port we were given

    # client = EchoClient(ip, port, message=open('/tmp/1.txt', 'r').read())

    asyncore.loop()
