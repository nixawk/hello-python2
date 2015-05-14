#!/usr/bin/env python
# -*- coding: utf8 -*-

import paramiko

BUFSIZE = 1024


def ssh_command(ip, username, password, command):
    """makes a connection to an SSH server and runs a single command"""
    client = paramiko.SSHClient()

    # Paramiko supports authentication with keys instead of password
    # authentication
    # client.load_host_keys('/home/justin/.ssh/known_hosts')

    # set the policy to accept SSH keys for the SSH server we're connecting to
    # and make the connection
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(ip, username=username, password=password)
    ssh_session = client.get_transport().open_session()

    if ssh_session.active:
        # execute command
        ssh_session.exec_command(command)
        print ssh_session.recv(BUFSIZE)
    return

# connect to openssh server, and execute commands
ssh_command('192.168.1.107', 'root', 'password', 'id')
