#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Python's select() function is a direct interface to the underly operating system implementation.
It monitors sockets, open files, and pipes (anything with a fileno() method that returns a valid file
descriptor) until they become readable or writable or a communication error occurs. select()
makes it easier to monitor multiple connections at the same time, and is more efficient than
writing a polling loop in Python using socket timeouts, because the monitor happens in the
operating system network layer, instead of the interpreter.
"""

import functools
import logging
import select
import socket
import queue
import sys


logging.basicConfig(level=logging.DEBUG, format="%(asctime)s : %(funcName)s %(message)s")
log = logging.getLogger(__name__)


def handle_KeyboardInterrupt(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt:
            print('\nQuit with Ctrl^C')
    return wrapper


class LazyEchoServer(object):

    def __init__(self, address, family=socket.AF_INET, sock_type=socket.SOCK_STREAM):
        self.address = address
        self.family = family
        self.sock_type = sock_type

        self.sock = None
        self.inputs = []
        self.outputs = []
        self.message_queues = {}
        self.buffersize = 1024
        self.timeout = 60

    def __enter__(self):
        self.sock = socket.socket(self.family, self.sock_type)
        self.sock.setblocking(False)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(self.address)
        self.sock.listen(5)

        self.inputs.append(self.sock)
        log.debug('    server is listening on %s', self.address)

        return self

    def __exit__(self, *exc):
        self.sock.close()
        self.sock = None

    @handle_KeyboardInterrupt
    def serve_forever(self):
        """
        select(rlist, wlist, xlist[, timeout]) -> (rlist, wlist, xlist)

        Wait until one or more file descriptors are ready for some kind of I/O.
        The first three arguments are sequences of file descriptors to be waited for:
        rlist -- wait until ready for reading
        wlist -- wait until ready for writing
        xlist -- wait for an ``exceptional condition''
        """
        while self.inputs:
            readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs, self.timeout)

            map(self.handle_readable_sock, readable)
            map(self.handle_writable_sock, writable)
            map(self.handle_exceptional_sock, exceptional)

    def handle_readable_sock(self, sock):
        if sock is self.sock:
            connection, client_address = sock.accept()
            connection.setblocking(False)
            self.inputs.append(connection)
            self.message_queues[connection] = queue.Queue()

            log.debug('    readable condition on %s', connection.getpeername())
        else:
            data = sock.recv(self.buffersize)
            if data:
                log.debug('    received {!r} from {}'.format(data, sock.getpeername()))
                self.message_queues[sock].put(data)

                if sock not in self.outputs:
                    self.outputs.append(sock)
            else:
                if sock in self.outputs:
                    self.outputs.remove(sock)
                self.inputs.remove(sock)
                sock.close()

                del self.message_queues[sock]

    def handle_writable_sock(self, sock):
        log.debug('    writable condition on %s', sock.getpeername())

        try:
            next_msg = self.message_queues[sock].get_nowait()
        except queue.Empty:
            self.outputs.remove(sock)
        else:
            log.debug('    sending %r to %s', next_msg, sock.getpeername())
            sock.send(next_msg)

    def handle_exceptional_sock(self, sock):
        log.debug('    exception condition on %s', sock.getpeername())

        self.inputs.remove(sock)
        if sock in self.outputs:
            self.outputs.remove(sock)
        sock.close()

        del self.message_queues[sock]


if __name__ == '__main__':
    address = ('localhost', 10000)
    with LazyEchoServer(address) as server:
        server.serve_forever()