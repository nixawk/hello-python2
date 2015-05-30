#!/usr/bin/env python
# -*- coding: utf8 -*-

import socket


BUFSIZE = 65535


def mac2byte(addr):
    """convert mac address to byte
    """

    mac = []

    if ':' in addr:
        mac = addr.split(':')
    elif '-' in addr:
        mac = addr.split('-')
    else:
        raise ValueError('error: MAC address not valid')

    macbyte = [chr(int(i, 16) for i in mac)]

    return "".join(macbyte)


def networkinfo():
    """get network information (root privilege needed)
    """

    # ETH_P_IP (0x0800)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(0x800))

    # information
    ifname = None
    ifaddr = None
    ifmac = None
    gateway = None

    try:
        while True:

            # return ip address
            socket.gethostbyname('www.google.com')

            # addr - ('enp0s25', 2048, 0, 1, '\x80\x89\x17}\xa1 ')
            # addr:
            #     [0] Interface
            #     [1] Physical layer protocol (ETH_P_IP for IP)
            #     [2] Packet Type (incoming, outgoing...)
            #     [3] ARP Hardware type

            data, addr = sock.recvfrom(BUFSIZE)

            # socket.PACKET_OUTGOING
            # - packet originated from the local host Discard

            # socket.PACKET_HOST
            # - packet addressed to the local host

            if addr[2] == socket.PACKET_HOST and addr[0] not in ('lo'):
                break

    # disconnect to internet
    except socket.gaierror as err:
        print err

    else:
        # get interface information
        ifname = addr[0]

        # ppp0 / tun0
        if ('ppp' in ifname) or ('tun' in ifname):
            ifmac = mac2byte('00:00:00:00:00:00')
            gateway = mac2byte('00:00:00:00:00:00')
            IPHI = 0    # for ppp interfaces
        else:
            ifmac = data[:6]
            gateway = data[6:12]
            IPHI = 14   # for eth interfaces

        # interface ip address
        ifaddr = socket.inet_ntoa(data[IPHI+16:IPHI+20])

    finally:
        sock.close()
        return ifname, ifaddr, ifmac, gateway


if __name__ == "__main__":
    print networkinfo()

# http://www.pythonforpentesting.com/2014/09/packet-injection-capturing-response.html
# http://stackoverflow.com/questions/159137/getting-mac-address
