# Copyright 2017 <Nixawk>. All Rights Reserved.
# Licensed to GNU under a Contributor Agreement.


"""UDP, called USER DATAGRAM PROTOCOL. Please read https://tools.ietf.org/html/rfc768 for more protocol details."""


from __future__ import print_function
from __future__ import absolute_import

# from ctypes import *

import ctypes
import socket

# UDP provides  a procedure  for application  programs  to send
# messages  to other programs  with a minimum  of protocol mechanism.  The
# protocol  is transaction oriented, and delivery and duplicate protection
# are not guaranteed.  Applications requiring ordered reliable delivery of
# streams of data should use the Transmission Control Protocol

# Format
# ------


#                   0      7 8     15 16    23 24    31
#                  +--------+--------+--------+--------+
#                  |     Source      |   Destination   |
#                  |      Port       |      Port       |
#                  +--------+--------+--------+--------+
#                  |                 |                 |
#                  |     Length      |    Checksum     |
#                  +--------+--------+--------+--------+
#                  |
#                  |          data octets ...
#                  +---------------- ...

#                       User Datagram Header Format


# Source Port is an optional field, when meaningful, it indicates the port
# of the sending  process,  and may be assumed  to be the port  to which a
# reply should  be addressed  in the absence of any other information.  If
# not used, a value of zero is inserted.

# Destination  Port has a meaning  within  the  context  of  a  particular
# internet destination address.

# Length  is the length  in octets  of this user datagram  including  this
# header  and the data.   (This  means  the minimum value of the length is
# eight.)

UDP_MIN_HDRLEN = 8

# Checksum is the 16-bit one's complement of the one's complement sum of a
# pseudo header of information from the IP header, the UDP header, and the
# data,  padded  with zero octets  at the end (if  necessary)  to  make  a
# multiple of two octets.

# The pseudo  header  conceptually prefixed to the UDP header contains the
# source  address,  the destination  address,  the protocol,  and the  UDP
# length.   This information gives protection against misrouted datagrams.
# This checksum procedure is the same as is used in TCP.

#                   0      7 8     15 16    23 24    31
#                  +--------+--------+--------+--------+
#                  |          source address           |
#                  +--------+--------+--------+--------+
#                  |        destination address        |
#                  +--------+--------+--------+--------+
#                  |  zero  |protocol|   UDP length    |
#                  +--------+--------+--------+--------+

# If the computed  checksum  is zero,  it is transmitted  as all ones (the
# equivalent  in one's complement  arithmetic).   An all zero  transmitted
# checksum  value means that the transmitter  generated  no checksum  (for
# debugging or for higher level protocols that don't care).

class UDP(ctypes.BigEndianStructure):

    _align_ = 1

    _fields_ = [
        ('udp_sport',    ctypes.c_uint16),   # /* 32 bit Source Address */
        ('udp_dport',    ctypes.c_uint16),   # /* 32 bit Destination Address */
        ('udp_len',      ctypes.c_uint16),   # /* 16 bit length = header + data */
        ('udp_checksum', ctypes.c_uint16),   # /* 16 bit UDP Checksum */

        # ('udp_data', bytes)                # /* Possible Lengths, UDP Data */
    ]

    def __init__(self, udp_sport=0, udp_dport=0, udp_len=UDP_MIN_HDRLEN, udp_checksum=0, udp_data=b''):
        super(UDP, self).__init__(udp_sport, udp_dport, udp_len, udp_checksum)

        self.udp_data = udp_data

    def pack(self):
        '''pack an udp object into binary data.'''
        bindata = ctypes.string_at(ctypes.addressof(self), ctypes.sizeof(self))
        bindata += self.udp_data

        return bindata

    def unpack(self, buf):
        '''unpack binary buf into an udp object.'''

        if not isinstance(buf, bytes):
            raise Exception('unpack buffer must be a byte string.')

        cstring = ctypes.create_string_buffer(buf)
        ctype_instance = ctypes.cast(ctypes.pointer(cstring), ctypes.POINTER(UDP)).contents

        ctype_instance.udp_data = buf[UDP_MIN_HDRLEN:len(buf)]          # /* UDP Data */

        return ctype_instance

    def wireshark_print(self):
        '''output binary packet as what wireshark prints.'''
        print("User Datagram Protocol, Src Port: %d, Dst Post: %d" % (self.udp_dport, self.udp_dport))
        print("Source Port: %d" % self.udp_sport)
        print("Destination Port: %d" % self.udp_dport)
        print("Length: %d" % self.udp_len)
        print("Checksum: 0x%04x" % self.checksum())

    def checksum(self, msg=None):
        '''sum protocol checksum'''

        # https://github.com/emamirazavi/python3-ping/blob/master/ping.py#L246
        # https://stackoverflow.com/questions/3949726/calculate-ip-checksum-in-python

        self.udp_checksum = 0                  # Initialize ip_sum to zero (First)
        msg = msg if msg else self.raw   # calculate                 (Second)

        f = lambda a, b: ((a + b) & 0xffff) + ((a + b) >> 16)
        n = len(msg)
        cnt = (n // 2) * 2
        s = 0

        for i in range(0, cnt, 2):
            x = msg[i]
            y = msg[i+1]

            try:
                w = ord(x) + (ord(y) << 8)  # Python 3
            except:
                w = x + (y << 8)            # Python 2

            s = f(s, w)

        s &= 0xffffffff
        
        s += (s >> 16)
        s = ~s & 0xffff

        s = socket.htons(s)
        self.udp_checksum = s
        return s

    @property
    def raw(self):
        '''udp raw data'''
        return self.pack()

    def __str__(self):
        '''return packet binary as a string.'''
        return str(self.pack())

    def __len__(self):
        '''return packet length.'''
        return ctypes.sizeof(self)


if __name__ == '__main__':
    bindata = b'\x14\xe9\x14\xe9\x00\x30\x9b\xfd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0b\x5f\x67\x6f\x6f\x67\x6c\x65\x63\x61\x73\x74\x04\x5f\x74\x63\x70\x05\x6c\x6f\x63\x61\x6c\x00\x00\x0c\x80\x01'

    udp = UDP()
    udp.pack()
    udp.wireshark_print()

    newudp = udp.unpack(bindata)
    newudp.wireshark_print()


## References

# https://tools.ietf.org/html/rfc768