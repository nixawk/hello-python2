#!/usr/bin/env python
# -*- coding: utf8 -*-

# run it with root privilege
# http://stackoverflow.com/questions/29306747/python-sniffing-from-black-hat-python-book
# Black HAT PYTHON (page 40/41)

import socket
import struct
from ctypes import *


class IP(Structure):
    _fields_ = [
        ("ihl",           c_ubyte, 4),
        ("version",       c_ubyte, 4),
        ("tos",           c_ubyte, 8),
        ("len",           c_ushort, 16),
        ("id",            c_ushort, 16),
        ("offset",        c_ushort, 16),
        ("ttl",           c_ubyte, 8),
        ("protocol_num",  c_ubyte, 8),
        ("sum",           c_ushort, 16),
        ("src",           c_uint, 32),
        ("dst",           c_uint, 32)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        # human readable IP addresses
        self.src_address = socket.inet_ntoa(
            struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(
            struct.pack("<L", self.dst))

        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)


def linux_sniffer1(interface="eth0"):
    """capture more than (linux_sniffer2)"""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM)
    s.bind((interface, 0x0800))

    while True:
        msg, addr = s.recvfrom(65535)
        ip_header = IP(msg)

        print "Protocol: %s %s -> %s" % (ip_header.protocol,
                                         ip_header.src_address,
                                         ip_header.dst_address)


def linux_sniffer2(host):
    """capture package"""
    sniffer = socket.socket(socket.AF_INET,
                            socket.SOCK_RAW,
                            socket.IPPROTO_ICMP)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP,
                       socket.IP_HDRINCL,
                       1)

    while True:
        msg, addr = sniffer.recvfrom(65535)

        ip_header = IP(msg)

        print "Protocol: %s %s -> %s" % (ip_header.protocol,
                                         ip_header.src_address,
                                         ip_header.dst_address)


def win_sniffer(host):
    """capature windows package"""
    sniffer = socket.socket(socket.AF_INET,
                            socket.SOCK_RAW,
                            socket.IPPROTO_IP)
    sniffer.setopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sniffer.bind((host, 0))
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            msg, addr = sniffer.recvfrom(1024)
            print addr
    except:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

linux_sniffer1("enp0s25")
# linux_sniffer2("192.168.1.108")

# win_sniffer("192.168.100.102")
