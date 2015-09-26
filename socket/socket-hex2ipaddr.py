#!/usr/bin/env python
# -*- coding: utf8 -*-

import socket
import struct


def hex2ipaddr(hexaddr):
    return socket.inet_ntoa(struct.pack("<L", int("%s" % hexaddr, 16)))


def hex2port(hexaddr):
    return int("%s" % hexaddr, 16)


if __name__ == '__main__':
    # linux/unix : cat /proc/net/tcp
    print hex2ipaddr("AB06020A")
    print hex2port("0051")
