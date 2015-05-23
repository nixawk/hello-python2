#!/usr/bin/env python
# -*- coding: utf8 -*-

from scapy.all import *


# disable verbose mode
conf.verb = 0


def parse_dnspkt(pkt):
    """ parse dns request / response packet """
    if pkt and pkt.haslayer('UDP') and pkt.haslayer('DNS'):
        ip = pkt['IP']
        udp = pkt['UDP']
        dns = pkt['DNS']

        # dns query packet
        if int(udp.dport) == 53:
            qname = dns.qd.qname

            print "\n[*] request: %s:%d -> %s:%d : %s" % (
                ip.src, udp.sport,
                ip.dst, udp.dport,
                qname)

        # dns reply packet
        elif int(udp.sport) == 53:
            # dns DNSRR count (answer count)
            for i in range(dns.ancount):
                dnsrr = dns.an[i]
                print "[*] response: %s:%s <- %s:%d : %s - %s" % (
                    ip.dst, udp.dport,
                    ip.src, udp.sport,
                    dnsrr.rrname, dnsrr.rdata)


def sniffer():
    sniff(filter="udp port 53", prn=parse_dnspkt)


if __name__ == "__main__":
    sniffer()
