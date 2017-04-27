#!/usr/bin/python
# -*- coding: utf-8 -*-

from ctypes import *
import socket
import struct
import binascii
import logging

# Mac OSX : No
# Linux   : Yes

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__file__)


class ARP(Structure):

    _pack_ = 1

    _fields_ = [
        ('destination', c_uint8 * 6),
        ('source', c_uint8 * 6),
        ('type', c_uint16),
        ('hardware_type', c_uint16),
        ('protocol_type', c_uint16),
        ('hardware_size', c_uint8),
        ('protocol_size', c_uint8),
        ('opcode', c_uint16),
        ('sender_mac_addr', c_uint8 * 6),
        ('sender_ip_addr', c_uint32),
        ('target_mac_addr', c_uint8 * 6),
        ('target_ip_addr', c_uint32)
    ]

    def __new__(self, buffer=None):
        return self.from_buffer_copy(buffer)

    def pack(self, buffer):
        return string_at(byref(buffer), sizeof(buffer))

    def int2ip(self, integer):
        return socket.inet_ntoa(struct.pack("<I", integer))

    def __init__(self, buffer):
        log.info("Ether II - destination     : {}".format(binascii.hexlify(self.pack(self.destination))))
        log.info("Ether II - source          : {}".format(binascii.hexlify(self.pack(self.source))))
        log.info("Ether II - type            : {}".format(hex(self.type)))
        log.info("     ARP - hardware_type   : {}".format(hex(self.hardware_type)))
        log.info("     ARP - protocol_type   : {}".format(hex(self.protocol_type)))
        log.info("     ARP - hardware_size   : {}".format(hex(self.hardware_size)))
        log.info("     ARP - protocol_size   : {}".format(hex(self.protocol_size)))
        log.info("     ARP - opcode          : {}".format(hex(self.opcode)))
        log.info("     ARP - sender_mac_addr : {}".format(binascii.hexlify(self.pack(self.sender_mac_addr))))
        log.info("     ARP - sender_ip_addr  : {}".format(self.int2ip(self.sender_ip_addr)))
        log.info("     ARP - target_mac_addr : {}".format(binascii.hexlify(self.pack(self.target_mac_addr))))
        log.info("     ARP - target_ip_addr  : {}".format(self.int2ip(self.target_ip_addr)))


def send_arp_request(device, src_ip, dst_ip):
    # Mac OSX: socket.AF_PACKET -- not found.
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
    s.bind((device, socket.SOCK_RAW))

    src_mac = s.getsockname()[4]    # get current mac address
    src_ip = struct.pack('!4B', *[int(x) for x in src_ip.split('.')])
    dst_ip = struct.pack('!4B', *[int(x) for x in dst_ip.split('.')])

    arp_request = [
        # Ethernet II
        '\xff\xff\xff\xff\xff\xff',    # Destination: Broadcast
        src_mac,                       # Source
        '\x08\x06',                    # Type

        # Address Resolution Protocol
        '\x00\x01',                    # Hardware type: Ethernet
        '\x08\x00',                    # Protocol type
        '\x06',                        # Hardware size
        '\x04',                        # Protocol size
        '\x00\x01',                    # Opcode: request
        src_mac,                       # Sender MAC address
        src_ip,                        # Sender IP address
        '\x00\x00\x00\x00\x00\x00',    # Target MAC address
        dst_ip                         # Target IP address
    ]

    proto = "".join(arp_request)
    s.send(proto)

    data = s.recv(1024)
    ARP(data)

    s.close()


if __name__ == '__main__':
    device = 'eth0'
    src_ip = '192.168.53.156'
    dst_ip = '192.168.53.141'

    send_arp_request(device, src_ip, dst_ip)

## References

# https://github.com/krig/send_arp.py/blob/master/send_arp.py
# http://stackoverflow.com/questions/1825715/how-to-pack-and-unpack-using-ctypes-structure-str
# http://stackoverflow.com/questions/18536182/parsing-binary-data-into-ctypes-structure-object-via-readinto
# http://stackoverflow.com/questions/5619685/conversion-from-ip-string-to-integer-and-backward-in-python
