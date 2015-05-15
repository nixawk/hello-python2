#!/usr/bin/env python
# -*- coding: utf8 -*-

# run it with root privilege

import socket


def linux_sniffer1(interface="eth0"):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM)
    s.bind((interface, 0x0800))

    while True:
        msg, addr = s.recvfrom(1024)
        print "<---- ", addr


def linux_sniffer2(host):
    sniffer = socket.socket(socket.AF_INET,
                            socket.SOCK_RAW,
                            socket.IPPROTO_TCP)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP,
                       socket.IP_HDRINCL,
                       1)

    while True:
        msg, addr = sniffer.recvfrom(1024)
        print "<---- ", addr


def win_sniffer(host):
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

# linux_sniffer1("eth0")
# linux_sniffer2("192.168.100.108")

win_sniffer("192.168.100.102")
