#!/usr/bin/env python
# -*- coding: utf8 -*-

"""
execte demo py with root privilege, and finish double dns query as follow.

    $ nslookup search.yahoo.com
    $ nslookup github.com

dns sniffer will parse dns requests and responses automatically.

    root:scapy/ #  python scapy-dns_sniff.py
    WARNING: No route found for IPv6 destination :: (no default route?)

    [*] request: 192.168.1.108:49771 -> 192.168.1.1:53 : search.yahoo.com.
    [*] response: 192.168.1.108:49771 <- 192.168.1.1:53 : search.yahoo.com. - ds-global.l7.search.ystg1.b.yahoo.com.
    [*] response: 192.168.1.108:49771 <- 192.168.1.1:53 : ds-global.l7.search.ystg1.b.yahoo.com. - ds-any-global.l7.search.ysta1.b.yahoo.com.
    [*] response: 192.168.1.108:49771 <- 192.168.1.1:53 : ds-any-global.l7.search.ysta1.b.yahoo.com. - 188.125.66.104

    [*] request: 192.168.1.108:40813 -> 192.168.1.1:53 : github.com.
    [*] response: 192.168.1.108:40813 <- 192.168.1.1:53 : github.com. - 192.30.252.128

"""

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
