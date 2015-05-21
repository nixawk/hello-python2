#!/usr/bin/env python
# -*- coding: utf8 -*-

import asyncore
import logging


logging.basicConfig(level=logging.DEBUG,
                    format='[*] %(name)s - %(funcName)16s - %(message)s')


class EchoHandler(asyncore.dispatcher_with_send):
    def __init__(self, _sock=None, _map=None):
        self.logger = logging.getLogger('EchoHandler')
        self.BUFSIZE = 1024

        asyncore.dispatcher.__init__(self, _sock, _map)
        self.out_buffer = ''

    def readable(self):
        return True

    def writable(self):
        return False

    def handle_read(self):
        data = self.recv(self.BUFSIZE)
        self.logger.debug('%d bytes | client <- server' % len(data))

        self.send(data)
        self.logger.debug('%d bytes | client -> server' % len(data))

    def handle_writable(self):
        pass

    def handle_error(self):
        self.logger.debug('socket exception')

    def handle_close(self):
        self.close()


class EchoServer(asyncore.dispatcher):
    def __init__(self):
        self.logger = logging.getLogger('EchoServer')

        asyncore.dispatcher.__init__(self)

        self.create_socket(asyncore.socket.AF_INET,
                           asyncore.socket.SOCK_STREAM)

        # socket reuse address
        self.set_reuse_addr()

        self.logger.debug('create a socket')

        self.bind(('localhost', 8080))
        self.logger.debug('bind socket address')

        self.listen(1)
        self.logger.debug('listen socket on %s:%s' % ('localhost', 8080))

    def handle_accept(self):
        client, caddr = self.accept()
        self.logger.debug('client: %s:%s' % caddr)

        EchoHandler(client)
        self.logger.debug('Enter into EchoHandler')


if __name__ == "__main__":
    EchoServer()
    asyncore.loop()
