#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Copyright (c) 2008 Doug Hellmann All rights reserved.
#


import sys
import SocketServer


class Echo(SocketServer.BaseRequestHandler):

    def handle(self):
        # Get some bytes and echo them back to the client.  There is
        # no need to decode them, since they are not used.
        data = self.request.recv(1024)
        self.request.send(data)
        return


class PassThrough(object):

    def __init__(self, other):
        self.other = other

    def write(self, data):
        print 'Writing :', repr(data)
        return self.other.write(data)

    def read(self, size=-1):
        print 'Reading :',
        data = self.other.read(size)
        print repr(data)
        return data

    def flush(self):
        return self.other.flush()

    def close(self):
        return self.other.close()


if __name__ == '__main__':
    import codecs
    import socket
    import threading

    address = ('localhost', 0)  # let the kernel give us a port
    server = SocketServer.TCPServer(address, Echo)
    ip, port = server.server_address  # find out what port we were given

    t = threading.Thread(target=server.serve_forever)
    t.setDaemon(True)  # don't hang on exit
    t.start()

    # Connect to the server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))

    # Wrap the socket with a reader and writer.
    incoming = codecs.getreader('utf-8')(PassThrough(s.makefile('r')))
    outgoing = codecs.getwriter('utf-8')(PassThrough(s.makefile('w')))

    # Send the data
    text = u'pi: π'
    print 'Sending :', repr(text)
    outgoing.write(text)
    outgoing.flush()

    # Receive a response
    response = incoming.read()
    print 'Received:', repr(response)

    # Clean up
    s.close()
    server.socket.close()

    # Code from https://pymotw.com/2/codecs/index.html#unicode-primer
    # It will make an error as follow:
    """
root@sh:~# python socketserver_codecs.py
Traceback (most recent call last):
  File "socketserver_codecs.py", line 43, in <module>
    server = SocketServer.TCPServer(address, Echo)
  File "/usr/lib/python2.7/SocketServer.py", line 417, in __init__
    self.server_bind()
  File "/usr/lib/python2.7/SocketServer.py", line 431, in server_bind
    self.socket.bind(self.server_address)
  File "/usr/lib/python2.7/socket.py", line 228, in meth
    return getattr(self._sock,name)(*args)
socket.error: [Errno 98] Address already in use
"""
