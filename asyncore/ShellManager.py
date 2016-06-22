#!/usr/bin/env python
# -*- coding: utf8 -*-

import asyncore
import logging
import sys


logging.basicConfig(level=logging.DEBUG,
                    format='[*] %(name)s - %(funcName)16s - %(message)s')


class ConsoleHandler(asyncore.file_dispatcher):
    """Enable console interactive for socket read/write.
    """
    def __init__(self, sender, file):
        asyncore.file_dispatcher.__init__(self, file)
        self.current_shell = sender
        self.BUFSIZE = 1024

    def handle_read(self):
        self.current_shell.out_buffer += self.recv(self.BUFSIZE)


class ShellManager(asyncore.dispatcher):
    """Handle tcp in-connections, ex: send commands to targets.
    """
    def __init__(self, _sock=None, _map=None):
        self.logger = logging.getLogger('ShellManager')
        self.BUFSIZE = 1024

        asyncore.dispatcher.__init__(self, _sock, _map)
        self.out_buffer = ''

    def handle_read(self):
        """Called when the asynchronous loop detects that a read() call on
           the channel's socket will succeed."""
        data = self.recv(self.BUFSIZE)
        self.logger.debug('%d bytes | client <- server' % len(data))
        print(data.strip())
        # self.send(data)
        self.logger.debug('%d bytes | client -> server' % len(data))

    def handle_write(self):
        """Called when the asynchronous loop detects that a writable
           socket can be written. Often this method will implement the
           necessary buffering for performance. For example:
        """
        if self.out_buffer != "":
            sent = self.send(self.out_buffer)
            self.out_buffer = self.out_buffer[sent:]

    def handle_error(self):
        """Called when an exception is raised and not otherwise handled.
           The default version prints a condensed traceback.
        """
        self.logger.debug('socket exception')

    def handle_close(self):
        """Called when the socket is closed.
        """
        self.close()


class Listener(asyncore.dispatcher):
    """Start a tcp listener (default: 127.0.0.1:4444), and wait for connections.
       If a new connection, `ShellManager' will try to handle it.
    """
    def __init__(self, addr=('127.0.0.1', 4444), max_connections=4):
        self.logger = logging.getLogger('Listener')

        asyncore.dispatcher.__init__(self)
        self.logger.debug('create a socket')
        self.create_socket(asyncore.socket.AF_INET,
                           asyncore.socket.SOCK_STREAM)

        # socket reuse address
        self.set_reuse_addr()

        self.bind(addr)
        self.logger.debug('bind socket address')

        self.listen(max_connections)
        self.logger.debug('listen socket on %s:%s' % addr)

    def handle_accept(self):
        client, caddr = self.accept()
        self.logger.debug('client: %s:%s' % caddr)

        self.logger.debug('Enter into ShellManager')
        ConsoleHandler(ShellManager(client), sys.stdin)


if __name__ == "__main__":
    Listener()
    asyncore.loop()


# https://parijatmishra.wordpress.com/2008/01/04/writing-a-server-with-pythons-asyncore-module/
# http://stackoverflow.com/questions/7312977/asyncore-loop-and-raw-input-problem
# http://code.activestate.com/recipes/576967-asynchronous-pipe-communication-using-asyncore/
# https://pexpect.readthedocs.io/en/stable/
