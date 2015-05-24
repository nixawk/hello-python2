#!/usr/bin/env python
# -*- coding: utf8 -*-

"""
TCP SYN:

    1. [client] ---- SYN (seq=0, ack=0)     ----> [server]
    2. [server] ---- SYN+ACK (seq=1, ack=0) ----> [client]
    3. [client] ---- RST (...)              ----> [server]

if server sends a tcp with flags(SYN, ACK), client finds a port is open.


lab:scapy/ $  sudo python2 scapy-tcp_syn.py
WARNING: No route found for IPv6 destination :: (no default route?)

[?] syn scan 192.168.1.107:21
[!] 192.168.1.107 TCP/21 is filter|closed

[?] syn scan 192.168.1.107:25
[!] 192.168.1.107 TCP/25 is filter|closed

[?] syn scan 192.168.1.107:80
[*] 192.168.1.107 TCP/80 is open           <------

[?] syn scan 192.168.1.107:110
[!] 192.168.1.107 TCP/110 is filter|closed

[?] syn scan 192.168.1.107:443
[!] 192.168.1.107 TCP/443 is filter|closed

[?] syn scan 192.168.1.107:3389
[!] 192.168.1.107 TCP/3389 is filter|closed

[?] syn scan 192.168.1.107:8080
[!] 192.168.1.107 TCP/8080 is filter|closed
"""

from scapy.all import *
import logging


conf.verb = 0
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)


def syn(ip, port, timeout=0.8):
    syn = IP(version=4, dst=ip)/TCP(dport=port, flags="S")

    print "\n[?] syn scan %s:%s" % (ip, port)

    synack = sr1(syn, timeout=timeout)

    if synack and synack.haslayer('IP') and synack.haslayer('TCP'):

        synack_ip = synack.getlayer('IP')
        synack_tcp = synack.getlayer('TCP')

        if synack_tcp.flags == 0x012:
            #  tcp flags: SYN,ACK (0x012)

            print "[*] %s TCP/%s is open" % (ip, port)

            rst_ip = IP(src=synack_ip.dst,
                        dst=synack_ip.src)

            rst_tcp = TCP(sport=synack_tcp.dport,
                          dport=synack_tcp.sport,
                          seq=synack_tcp.ack+1,
                          ack=synack_tcp.seq,
                          flags="R")

            send(rst_ip/rst_tcp)
        else:
            print "[!] %s TCP/%s is filter|closed" % (ip, port)
    else:
        print "[!] %s TCP/%s is filter|closed" % (ip, port)


if __name__ == "__main__":
    for i in (21, 25, 80, 110, 443, 3389, 8080):
        syn('192.168.1.107', int(i))
