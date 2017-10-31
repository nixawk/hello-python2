#!/usr/bin/python
# -*- coding: utf-8 -*-

"""\
This module provides rsync operations and some related functions.

Functions:

Rsync.client_negotiate() -- recv rsync welcome/motd messages
Rsync.client_initialisation() -- send rsync VERSION query
Rsync.client_query() -- send rsync query string
Rsync.client_command() -- send rsync command string
Rsync.bruteforce() -- bruteforce a rsync server with username/password
Rsync.rsync_list() -- list a rsync server
Rsync.generate_challenge() -- read challenge string from rsync response
Rsync.generate_hash() -- generate password hash with password and challenge


Usages:

    $ python2.7 rsync.py mirrors.tripadvisor.com

    [{'comment': 'https://www.centos.org', 'name': 'centos'},
     {'comment': 'https://www.centos.org', 'name': 'centos-vault'},
     {'comment': 'https://www.ubuntu.com', 'name': 'ubuntu'},
     {'comment': 'https://www.ubuntu.com', 'name': 'releases'},
     {'comment': 'https://www.archlinux.org', 'name': 'archlinux'},
     {'comment': 'https://www.gnu.org', 'name': 'gnu'}]

    $ python2.7
    Python 2.7.13 (default, Jan 19 2017, 14:48:08)
    [GCC 6.3.0 20170118] on linux2
    Type "help", "copyright", "credits" or "license" for more information.
    >>> import rsync
    >>> rsync_client = rsync.Rsync("10.97.214.6", 873)
    >>> rsync_client.rsync_list()
    >>> rsync_client.modules_list
    [{'comment': 'The documents folder of Juan', 'name': 'code'}]
    >>> rsync_client.bruteforce("root", "password")
    True
    
"""

__author__  = "Nixawk"
__license__ = "GNU license"
__classes__ = ["RSYNC", "RSYNC_EXCEPTION"]

__all__     = [
    "bruteforce",
    "rsync_list",
    "rsync_auth"
]


import logging
import socket
import hashlib
import base64


logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)


SOCKET_TIMEOUT = 8.0
SOCKET_READ_BUFFERSIZE = 1024


class RSYNC_EXCEPTION(Exception):
    """Custom Rsync Exception"""
    pass


class Rsync(object):

    """
    $ ncat -v mirrors.tripadvisor.com 873
    Ncat: Version 7.00 ( https://nmap.org/ncat )
    Ncat: Connected to 199.102.235.174:873.
    @RSYNCD: 30.0
    @RSYNCD: 30.0
    #list
    centos          https://www.centos.org
    centos-vault    https://www.centos.org
    ubuntu          https://www.ubuntu.com
    releases        https://www.ubuntu.com
    archlinux       https://www.archlinux.org
    gnu             https://www.gnu.org
    @RSYNCD: EXIT
    """

    MAGIC_HEADER     = '@RSYNCD:'
    HEADER_VERSION   = ''

    RSYNC_EXIT       = '@RSYNCD: EXIT'
    RSYNC_AUTH_REQ   = '@RSYNCD: AUTHREQD'
    RSYNC_AUTH_OK    = '@RSYNCD: OK'

    def __init__(self, host, port):
        """class __init__ method"""
        self.rsync_host = host  # remote rsync service host
        self.rsync_port = port  # remote rsync service port
        self.rsync_sock = None  # python socket object
        self.connections = []
        self.modules_list = []

    def __enter__(self):
        """support context manager"""
        self.connect()
        self.connections.append(self.rsync_sock)

        return self

    def __exit__(self, *exc):
        """support context manager"""
        self.rsync_sock = self.connections.pop()
        self.disconnect()

    def connect(self):
        """connect to rsync server"""
        self.rsync_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.rsync_sock.settimeout(SOCKET_TIMEOUT)
        self.rsync_sock.connect((self.rsync_host, self.rsync_port))

    def disconnect(self):
        """disconnect from rsync server"""
        self.rsync_sock.close()
        self.rsync_sock = None

    def read(self):
        """receive data from rsync server"""
        data = ''
        try:
            while True:
                _ = self.rsync_sock.recv(SOCKET_READ_BUFFERSIZE)
                if not _: break
                data += _
        except Exception as err:
            pass
        return data

    def write(self, data):
        """send data to rsync server"""
        self.rsync_sock.send(data)

    def client_negotiate(self):
        """receive rsync welcome message"""
        data = self.read()

        if not data:
            raise RSYNC_EXCEPTION("rsync client recvs no response")

        if not (self.MAGIC_HEADER in data):
            raise RSYNC_EXCEPTION("rsync client recvs error protocol")

        # [data] examples:

        # '@RSYNCD: 30.0\n'

        # "@RSYNCD: 31.0\nWelcome to the ftp-stud.hs-esslingen.de archives.\n\nIf have any unusual problems, please report them via e-mail to\nrsync@ftp-stud.hs-esslingen.de.\n\n  All transfers are logged.\n  If you don't like this policy, then disconnect now.\n  This server does not support --checksum (-c)\n  This server does not support --compress (-z)\n\n\n"

        ver, motd = data.split("\n", 1)

        _, self.HEADER_VERSION = ver.split(" ", 1)
        if not self.HEADER_VERSION:
            raise RSYNC_EXCEPTION("rsync client fails to recv rsync version")

    def client_initialisation(self):
        """send rsync file rsynchroniser query"""
        rsync_file_rsynchroniser = [
            self.MAGIC_HEADER,
            self.HEADER_VERSION,
            "\n"
        ]
        rsync_file_rsynchroniser = "".join(rsync_file_rsynchroniser)
        self.write(rsync_file_rsynchroniser)

    def client_query(self, data):
        """send query string to rsync server"""
        self.write(data)

    def client_command(self, data):
        """send command string to rsync server"""
        self.write(data)

    def rsync_list(self):
        """list all records from rsync server"""
        # $ ncat -v mirrors.tripadvisor.com 873
        # Ncat: Version 7.00 ( https://nmap.org/ncat )
        # Ncat: Connected to 199.102.235.174:873.
        # @RSYNCD: 30.0
        # @RSYNCD: 30.0

        # centos          https://www.centos.org
        # centos-vault    https://www.centos.org
        # ubuntu          https://www.ubuntu.com
        # releases        https://www.ubuntu.com
        # archlinux       https://www.archlinux.org
        # gnu             https://www.gnu.org

        self.connect()
        self.client_negotiate()
        self.client_initialisation()
        self.client_query("\n")

        raw = self.read()  # [@RSYNCD: EXIT]
        if not raw:
            raise RSYNC_EXCEPTION("rsync client fails to list records")

        lines = raw.split("\n")
        for line in lines:
            if not (line and "\t" in line): continue
            name, comment = line.split("\t", 1)
            name = name.strip()
            module_info = {
                "name": name,
                "comment": comment
            }

            self.modules_list.append(module_info)

        self.disconnect()

    def bruteforce(self, username, password):
        """bruteforce rsync server with creds"""
        self.rsync_list()
        for module_list in self.modules_list:
            if self.rsync_auth(username, password, module_list['name']):
                return True

        return False

    def generate_challenge(self, data):
        """generate challenge string from rsync response"""

        # Line 59, From rsync/authenticate.c, original:
        # void gen_challenge(const char *addr, char *challenge)

        # '@RSYNCD: 31.0\n@RSYNCD: AUTHREQD qUah8Knxn+k1k9LINf4fkg\n'
        challenge = filter(
            lambda x: self.RSYNC_AUTH_REQ in x,
            data.split("\n"))

        if not challenge:
            raise RSYNC_EXCEPTION("fails to recv rsync challenge response")

        challenge = challenge[0]
        challenge = challenge.replace(self.RSYNC_AUTH_REQ, "")
        challenge = challenge.strip()

        return challenge

    def generate_hash(self, password, challenge):
        """generate rsync password hash"""

        # Line 83, From rsync/authenticate.c, original:
        # void generate_hash(const char *in, const char *challenge, char *out)

        md5 = hashlib.md5()
        md5.update(password)
        md5.update(challenge)

        pwdhash = base64.b64encode(md5.digest())  # 'NCjPJpWP7VPP2dO7X0jhrw=='
        pwdhash = pwdhash.rstrip('==')

        return pwdhash

    def rsync_auth(self, username, password, modulename):
        """access a rsync module with creds"""

        # $ ncat -v 10.97.214.6 873
        # Ncat: Version 7.00 ( https://nmap.org/ncat )
        # Ncat: Connected to 10.97.214.6:873.
        # @RSYNCD: 31.0
        # @RSYNCD: 31.0
        # code
        # @RSYNCD: AUTHREQD kPbHY16SUmch6/WhA/4brQ

        # @ERROR: auth failed on module code

        self.connect()  # must reconnect here
        self.client_initialisation()
        self.client_query(modulename + "\n")

        # rsync challenge response (include str)
        rawdata = self.read()

        # no auth require
        # '@RSYNCD: 30.0\n@RSYNCD: OK\n'
        if rawdata and self.RSYNC_AUTH_OK in rawdata:
            return True

        # auth require
        challenge = self.generate_challenge(rawdata)
        pass_hash = self.generate_hash(password, challenge)

        self.client_command("{} {}\n".format(username, pass_hash))
        rawdata = self.read()

        # '@RSYNCD: OK\n'
        # '@ERROR: auth failed on module code\n'
        if rawdata and rawdata.startswith(self.RSYNC_AUTH_OK):
            return True

        self.disconnect()

        return False


if __name__ == "__main__":
    from pprint import pprint
    import sys, os

    argc = len(sys.argv)
    if argc == 2:
        host = sys.argv[1]
        port = 873
    elif argc == 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
    else:
        print("[*] python %s <host> <port, default: 873>" % os.path.basename(sys.argv[0]))
        sys.exit(1)

    rsync = Rsync(host, port)
    rsync.rsync_list()
    pprint(rsync.modules_list)



# References
# https://www.rfc-editor.org/rfc/rfc5781.txt
# https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/rsync/modules_list.rb
# http://rsync.samba.org/ftp/rsync/rsync.html
# https://rsync.samba.org/how-rsync-works.html
# https://github.com/rapid7/metasploit-framework/pull/6178
# https://www.wireshark.org/docs/dfref/r/rsync.html
# https://github.com/boundary/wireshark/blob/master/epan/dissectors/packet-rsync.c