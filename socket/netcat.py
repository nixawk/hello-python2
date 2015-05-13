#!/usr/bin/env python
# -*- coding: utf8 -*-

# Code netcat with Python
# Author: Nixawk

import socket
import select
import logging
import Queue
import sys
import subprocess

logging.basicConfig(level=logging.DEBUG,
                    format='[*] %(name)s - %(funcName)s - %(message)s')


class netcat(object):
    """python netcat """

    def __init__(self):
        # enable logging mode
        self.logger = logging.getLogger("server")
        self.logger.debug('enable logging mode')

        self.ssock = None   # server socket
        self.csock = None   # client socket

        # socket buffer size
        self.bufsize = 2048

        # commandshell/ functions
        self.commandshell = False

    def exec_command(self, cmd):
        """execute command"""
        proc = subprocess.Popen(cmd,
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                shell=True)

        cmd_output = proc.stdout.read()

        self.logger.debug("execute command - [%s]" % cmd.rstrip())

        return cmd_output

    def read_file(self, filepath):
        """get data from file"""
        self.logger.debug("read file")
        with open(filepath, 'r') as f:
            data = f.read()

        return data

    def stdio_handler(self):
        return sys.stdin.readline()

        # if self.csock:
        #     self.csock.send(data)

    def readable_handler(self, rsock, functions={}):
        """handle socket receive data"""
        if "commandshell" in functions and functions["commandshell"]:
            self.logger.debug('command shell mode is on')
            self.commandshell = True

        # wait for new connection
        if rsock is self.ssock:

            csock, caddr = self.ssock.accept()
            csock.setblocking(0)

            # socket which communicates with server
            self.csock = csock

            self.logger.debug('connection is from %s:%s' % caddr)

            # add socket to input monitor list
            if csock not in self.inputs:
                self.inputs.append(csock)
                self.message_queue[csock] = Queue.Queue()

        # handle stdin
        elif rsock is sys.stdin:
            data = self.stdio_handler()

            if data:
                self.csock.send(data)
                self.logger.debug("send %d bytes ->" % len(data))

            # self.csock.close()

        # handle established sock
        else:

            data = rsock.recv(self.bufsize)

            # data received
            if data:

                if self.commandshell:
                    cmd_output = self.exec_command(data)
                    rsock.send(cmd_output)
                else:
                    print data.rstrip()

                if rsock not in self.message_queue:
                    self.message_queue[rsock] = Queue.Queue()

                self.message_queue[rsock].put(data)
                self.logger.debug('<- %d bytes' % len(data))

            # no data returns
            else:
                if rsock in self.outputs:
                    self.outputs.remove(rsock)

                self.inputs.remove(rsock)
                self.logger.debug('remove socket from monitor list')

                del self.message_queue[rsock]
                self.logger.debug('delete socket message queue')

                self.logger.debug('close a socket')
                rsock.close()

    def writable_handler(self, wsock):
        """handle writable socket, send data to client"""
        try:
            data = self.message_queue.get_nowait()
        except Queue.Empty:
            if wsock in self.outputs:
                self.outputs.remove(wsock)
        finally:
            wsock.send(data)
            wsock.close()

    def exceptional_handler(self, esock):
        """handle exceptional socket"""

        self.inputs.remove(esock)
        if esock in self.outputs:
            self.outputs.remove(esock)
        esock.close()

        # Remove message queue
        del self.message_queues[esock]

    def listener(self, host, port, functions):
        """ server loop, wait for client connection"""
        """initializes tcp server socket, and start a listener"""

        # create server socket
        self.ssock = socket.socket(socket.AF_INET,
                                   socket.SOCK_STREAM,
                                   socket.IPPROTO_TCP)
        self.logger.debug('create a server socket')

        # disable socket blocking mode
        self.ssock.setblocking(0)

        # reuse socket
        self.ssock.setsockopt(socket.SOL_SOCKET,
                              socket.SO_REUSEADDR, 1)

        # bind socket address
        self.ssock.bind((host, port))
        self.logger.debug('bind socket address')

        # listen socket
        self.ssock.listen(2)
        self.logger.debug('listening on %s:%s' % (host, port))

        self.socket_handler(self.ssock, functions)

    def socket_handler(self, sock, functions):

        # select objects
        self.inputs = [sock, sys.stdin]
        self.outputs = []
        self.message_queue = {}
        # self.threads = []

        # which is communicated with server socket
        # self.csock = None

        while 1:
            # loop and select call, and wait for new connection
            readable, writable, exceptional = select.select(
                self.inputs,
                self.outputs,
                self.inputs)

            # self.logger.debug('monitoring socket with select call')

            # handle readable sockets
            for rsock in readable:
                self.readable_handler(rsock, functions)

            # handle writable sockets
            for wsock in writable:
                self.writable_handler(wsock)

            # handle exceptional sockets
            for esock in exceptional:
                self.exceptional_handler(esock)

    def client(self, host, port, functions={}):
        """tcp client socket"""
        sock = socket.socket(socket.AF_INET,
                             socket.SOCK_STREAM,
                             socket.IPPROTO_TCP)
        sock.connect((host, port))

        self.csock = sock
        # self.ssock = sock

        self.logger.debug('connected to %s:%s' % (host, port))

        self.socket_handler(self.csock, functions)


def usage():
    """show help information"""

    print "Netcat - Army Snife"
    print "\t[client mode] %s host port" % sys.argv[0]
    print "\t[server mode] %s -l -p 8080" % sys.argv[0]
    print "\t[server mode] %s -l -p 8080 -c" % sys.argv[0]

if __name__ == '__main__':
    """main function"""
    if len(sys.argv) == 3:
        # nc host port
        # nc.client('127.0.0.1', 8080, {})
        host = sys.argv[1]
        port = sys.argv[2]

        nc = netcat()
        nc.client(host, int(port), {})

    elif len(sys.argv) == 4:
        nc = netcat()

        if sys.argv[1] == '-l' and sys.argv[2] == '-p':
            # nc -l -p 8080
            nc.listener('', int(sys.argv[3]), {})
        else:
            usage()

    elif len(sys.argv) == 5:
        # listen on tcp/8080 for command shell
        # nc.listener('127.0.0.1', 8080, {"commandshell": False})
        nc = netcat()
        if sys.argv[1] == '-l' and sys.argv[2] == '-p' and sys.argv[4] == '-c':
            nc.listener('', int(sys.argv[3]), {"commandshell": True})
        else:
            usage()
    else:
        usage()
