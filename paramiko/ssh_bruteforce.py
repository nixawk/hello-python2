#!/usr/bin/python

import paramiko
import logging


logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)


def ssh_login(host, port, username, password, timeout=5):
    """Try ssh login with credentials.
    """
    boolret = False
    sshclient = paramiko.SSHClient()
    sshclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        sshclient.connect(host, port, username, password, pkey=None, timeout=timeout, allow_agent=False, look_for_keys=False)
        sshclient.close()
        log.info("Success: {}/{} : {} / {}".format(host, port, username, password))
        boolret = True
    except Exception as e:
        print(e)
        log.error("Error: {}/{} : {} / {}, {}".format(host, port, username, password, e))
    return boolret


host = '192.168.1.100'
port = 22
username = 'root'
password = 'password'


print ssh_login(host, port, username, password)
