# Copyright 2017 <Nixawk>. All Rights Reserved.
# Licensed to GNU under a Contributor Agreement.


"""TCP, called TRANSMISSION CONTROL PROTOCOL. Please read https://tools.ietf.org/html/rfc793 for more protocol details."""


from __future__ import print_function
from __future__ import absolute_import

# from ctypes import *

import ctypes
import socket


# TCP is based on concepts first described by Cerf and Kahn in [1].  The
# TCP fits into a layered protocol architecture just above a basic
# Internet Protocol [2] which provides a way for the TCP to send and
# receive variable-length segments of information enclosed in internet
# datagram "envelopes".  The internet datagram provides a means for
# addressing source and destination TCPs in different networks.  The
# internet protocol also deals with any fragmentation or reassembly of
# the TCP segments required to achieve transport and delivery through
# multiple networks and interconnecting gateways.  The internet protocol
# also carries information on the precedence, security classification
# and compartmentation of the TCP segments, so this information can be
# communicated end-to-end across multiple networks.

#                          Protocol Layering

#                       +---------------------+
#                       |     higher-level    |
#                       +---------------------+
#                       |        TCP          |
#                       +---------------------+
#                       |  internet protocol  |
#                       +---------------------+
#                       |communication network|
#                       +---------------------+

#  The following diagram illustrates the place of the TCP in the protocol
#  hierarchy:

#       +------+ +-----+ +-----+       +-----+
#       |Telnet| | FTP | |Voice|  ...  |     |  Application Level
#       +------+ +-----+ +-----+       +-----+
#             |   |         |             |
#            +-----+     +-----+       +-----+
#            | TCP |     | RTP |  ...  |     |  Host Level
#            +-----+     +-----+       +-----+
#               |           |             |
#            +-------------------------------+
#            |    Internet Protocol & ICMP   |  Gateway Level
#            +-------------------------------+
#                           |
#              +---------------------------+
#              |   Local Network Protocol  |    Network Level
#              +---------------------------+
#
#                         Protocol Relationships


# As noted above, the primary purpose of the TCP is to provide reliable,
# securable logical circuit or connection service between pairs of
# processes.  To provide this service on top of a less reliable internet
# communication system requires facilities in the following areas:

#   Basic Data Transfer
#   Reliability
#   Flow Control
#   Multiplexing
#   Connections
#   Precedence and Security

# Source Port:  16 bits

#   The source port number.

# Destination Port:  16 bits

#   The destination port number.

TCP_PORT_ZERO = 0

# Sequence Number:  32 bits

#   The sequence number of the first data octet in this segment (except
#   when SYN is present). If SYN is present the sequence number is the
#   initial sequence number (ISN) and the first data octet is ISN+1.

TCP_SEQ_SYNINIT = 0

# Acknowledgment Number:  32 bits

#   If the ACK control bit is set this field contains the value of the
#   next sequence number the sender of the segment is expecting to
#   receive.  Once a connection is established this is always sent.

TCP_SEQ_ACKINIT = 0

# Data Offset:  4 bits

#   The number of 32 bit words in the TCP Header.  This indicates where
#   the data begins.  The TCP header (even one including options) is an
#   integral number of 32 bits long.

# Reserved:  6 bits

#   Reserved for future use.  Must be zero.

# Control Bits:  6 bits (from left to right):

#   URG:  Urgent Pointer field significant
#   ACK:  Acknowledgment field significant
#   PSH:  Push Function
#   RST:  Reset the connection
#   SYN:  Synchronize sequence numbers
#   FIN:  No more data from sender

TH_FIN  = 0x01  # end of data
TH_SYN  = 0x02  # synchronize sequence numbers
TH_RST  = 0x04  # reset connection
TH_PUSH = 0x08  # push
TH_ACK  = 0x10  # acknowledgment number set
TH_URG  = 0x20  # urgent pointer set
TH_ECE  = 0x40  # ECN echo, RFC 3168
TH_CWR  = 0x80  # congestion window reduced

# Window:  16 bits

#   The number of data octets beginning with the one indicated in the
#   acknowledgment field which the sender of this segment is willing to
#   accept.

TCP_WIN_MAX     = 65535  # maximum (unscaled) window

# Checksum:  16 bits

#   The checksum field is the 16 bit one's complement of the one's
#   complement sum of all 16 bit words in the header and text.  If a
#   segment contains an odd number of header and text octets to be
#   checksummed, the last octet is padded on the right with zeros to
#   form a 16 bit word for checksum purposes.  The pad is not
#   transmitted as part of the segment.  While computing the checksum,
#   the checksum field itself is replaced with zeros.

# The checksum also covers a 96 bit pseudo header conceptually
# prefixed to the TCP header.  This pseudo header contains the Source
# Address, the Destination Address, the Protocol, and TCP length.
# This gives the TCP protection against misrouted segments.  This
# information is carried in the Internet Protocol and is transferred
# across the TCP/Network interface in the arguments or results of
# calls by the TCP on the IP.

#                  +--------+--------+--------+--------+
#                  |           Source Address          |
#                  +--------+--------+--------+--------+
#                  |         Destination Address       |
#                  +--------+--------+--------+--------+
#                  |  zero  |  PTCL  |    TCP Length   |
#                  +--------+--------+--------+--------+

#   The TCP Length is the TCP header length plus the data length in
#   octets (this is not an explicitly transmitted quantity, but is
#   computed), and it does not count the 12 octets of the pseudo
#   header.

# Urgent Pointer:  16 bits

#   This field communicates the current value of the urgent pointer as a
#   positive offset from the sequence number in this segment.  The
#   urgent pointer points to the sequence number of the octet following
#   the urgent data.  This field is only be interpreted in segments with
#   the URG control bit set.

# Options:  variable

#   Options may occupy space at the end of the TCP header and are a
#   multiple of 8 bits in length.  All options are included in the
#   checksum.  An option may begin on any octet boundary.  There are two
#   cases for the format of an option:

#     Case 1:  A single octet of option-kind.

#     Case 2:  An octet of option-kind, an octet of option-length, and
#              the actual option-data octets.

#   The option-length counts the two octets of option-kind and
#   option-length as well as the option-data octets.

#   Note that the list of options may be shorter than the data offset
#   field might imply.  The content of the header beyond the
#   End-of-Option option must be header padding (i.e., zero).

#   A TCP must implement all options.

#   Currently defined options include (kind indicated in octal):

#     Kind     Length    Meaning
#     ----     ------    -------
#      0         -       End of option list.
#      1         -       No-Operation.
#      2         4       Maximum Segment Size.


#   Specific Option Definitions

#     End of Option List

#       +--------+
#       |00000000|
#       +--------+
#        Kind=0

#       This option code indicates the end of the option list.  This
#       might not coincide with the end of the TCP header according to
#       the Data Offset field.  This is used at the end of all options,
#       not the end of each option, and need only be used if the end of
#       the options would not otherwise coincide with the end of the TCP
#       header.

#     No-Operation

#       +--------+
#       |00000001|
#       +--------+
#        Kind=1

#       This option code may be used between options, for example, to
#       align the beginning of a subsequent option on a word boundary.
#       There is no guarantee that senders will use this option, so
#       receivers must be prepared to process options even if they do
#       not begin on a word boundary.

#     Maximum Segment Size

#       +--------+--------+---------+--------+
#       |00000010|00000100|   max seg size   |
#       +--------+--------+---------+--------+
#        Kind=2   Length=4

#       Maximum Segment Size Option Data:  16 bits

#         If this option is present, then it communicates the maximum
#         receive segment size at the TCP which sends this segment.
#         This field must only be sent in the initial connection request
#         (i.e., in segments with the SYN control bit set).  If this
#         option is not used, any segment size is allowed.

# Padding:  variable

#   The TCP header padding is used to ensure that the TCP header ends
#   and data begins on a 32 bit boundary.  The padding is composed of
#   zeros.

TCP_MIN_MSS     = 88    # /* Minimal accepted MSS. It is (60+60+8) - (20+20). */
TCP_BASE_MSS    = 1024  # /* The least MTU to use for probing */

TCP_URG_VALID   = 0x0100
TCP_URG_NOTYET  = 0x0200
TCP_URG_READ    = 0x0400


class TCP(ctypes.BigEndianStructure):
    '''
      TCP Header Format


        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |          Source Port          |       Destination Port        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                        Sequence Number                        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                    Acknowledgment Number                      |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |  Data |           |U|A|P|R|S|F|                               |
       | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
       |       |           |G|K|H|T|N|N|                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |           Checksum            |         Urgent Pointer        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                    Options                    |    Padding    |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                             data                              |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                                TCP Header Format

              Note that one tick mark represents one bit position.
    '''

    _align_  = 1  # Page Alignment (64 bit is different with 32 bit)

    _fields_ = [
        ('tcp_sport',       ctypes.c_uint16),    # /* Source Port:  16 bits */
        ('tcp_dport',       ctypes.c_uint16),    # /* Destination Port:  16 bits */
        ('tcp_seqnum',      ctypes.c_uint32),    # /* Sequence Number:  32 bits. (2 ** 32 - 1 + 1 = 0) */
        ('tcp_acknum',      ctypes.c_uint32),    # /* Acknowledgment Number:  32 bits */
        ('tcp_dataoff',     ctypes.c_uint16, 4), # /* Data Offset:  4 bits */
        ('tcp_reserved',    ctypes.c_uint16, 6), # /* Reserved:  6 bits */
        ('tcp_ctrlbit',     ctypes.c_uint16, 6), # /* Control Bits:  6 bits (from left to right): */
        ('tcp_window',      ctypes.c_uint16),    # /* Window:  16 bits */
        ('tcp_checksum',    ctypes.c_uint16),    # /* Checksum:  16 bits */
        ('tcp_urgent_ptr',  ctypes.c_uint16),    # /* Urgent Pointer:  16 bits */

        # ('tcp_options', ),  # /* Options:  variable */
        # ('tcp_padding', ),  # /* Padding:  variable */\
        # ('tcp_data', )      # /* data   :  variable */
    ]

    def __init__(self,
            tcp_sport      = 0,
            tcp_dport      = 0,
            tcp_seqnum     = 0,
            tcp_acknum     = 0,
            tcp_dataoff    = 5,  # 5 << 4
            tcp_reserved   = 0,
            tcp_ctrlbit    = TH_SYN,
            tcp_window     = TCP_WIN_MAX,
            tcp_checksum   = 0,
            tcp_urgent_ptr = 0,
            tcp_options    = b'',
            tcp_data       = b''
        ):

        super(TCP, self).__init__(
            tcp_sport, tcp_dport, tcp_seqnum, tcp_acknum,
            tcp_dataoff, tcp_reserved, tcp_ctrlbit, tcp_window,
            tcp_checksum, tcp_urgent_ptr
        )

        self.tcp_options   = tcp_options
        self.tcp_data      = tcp_data

    def pack(self):
        '''pack an tcp object into binary data.'''
        bindata = ctypes.string_at(ctypes.addressof(self), ctypes.sizeof(self))
        bindata += self.tcp_options
        bindata += self.tcp_data

        return bindata

    def unpack(self, buf):
        '''unpack binary buf into an tcp object.'''

        if not isinstance(buf, bytes):
            raise Exception('unpack buffer must be a byte string.')

        cstring = ctypes.create_string_buffer(buf)
        ctype_instance = ctypes.cast(ctypes.pointer(cstring), ctypes.POINTER(TCP)).contents

        hdr_len  = ((ctype_instance.tcp_dataoff << 4) >> 2) # /* TCP Header Length */
        opt_len  = hdr_len - 20                             # /* TCP Option Length */
        data_len = len(buf) - hdr_len                       # /* TCP Data Length */

        ctype_instance.tcp_options = buf[20: 20 + opt_len]  # /* TCP Options */
        ctype_instance.tcp_data    = buf[hdr_len:]          # /* TCP Data */

        if (ctype_instance.tcp_ctrlbit & 0xFF) == TH_SYN:   # /* Relative Seq Number */
            ctype_instance.tcp_seqnum = TCP_SEQ_SYNINIT
            ctype_instance.tcp_acknum = TCP_SEQ_ACKINIT

        return ctype_instance

    def wireshark_print(self, buf=None):
        '''output binary packet as what wireshark prints.'''
        buf = buf if buf else self.raw
        ipinstance = self.unpack(buf)

        print("Transmission Control Protocol, Src Port: %d, Dst Port: %d, Seq: %d, Ack: %d, len: %d" % (
            ipinstance.tcp_sport, ipinstance.tcp_dport, ipinstance.tcp_seqnum, ipinstance.tcp_acknum,
            len(buf) - int((ipinstance.tcp_dataoff << 4) >> 2)
        ))
        print("Source Port: %d" % ipinstance.tcp_sport)
        print("Destination Port: %d" % ipinstance.tcp_dport)
        print("TCP Segment Len: %d" % (len(buf) - int((ipinstance.tcp_dataoff << 4) >> 2)))
        print("Sequence number: %d" % ipinstance.tcp_seqnum)
        print("Acknowledgment number: %d" % ipinstance.tcp_acknum)
        print("Header Length: %d" % ((ipinstance.tcp_dataoff << 4) >> 2))
        print("Flags: 0x%02x" % ipinstance.tcp_ctrlbit)
        print("Window size: %d" % ipinstance.tcp_window)
        print("Checksum: 0x%04x" % ipinstance.checksum())
        print("Urgent pointer: %d" % ipinstance.tcp_urgent_ptr)

    def checksum(self, msg=None):
        '''sum ip protocol checksum'''

        # https://github.com/emamirazavi/python3-ping/blob/master/ping.py#L246
        # https://stackoverflow.com/questions/3949726/calculate-ip-checksum-in-python

        self.tcp_checksum = 0                  # Initialize ip_sum to zero (First)
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
        self.tcp_checksum = s
        return s

    @property
    def raw(self):
        '''tcp raw data'''
        return self.pack()

    def __str__(self):
        '''return packet binary as a string.'''
        return str(self.pack())

    def __len__(self):
        '''return packet length.'''
        return ctypes.sizeof(self)


if __name__ == '__main__':
    # Translate Binary Data into TCP Object
    bindata = b'\xd5\x4b\x00\x87\x82\xee\x99\xe5\x00\x00\x00\x00\xb0\xc2\xff\xff\xf5\xe7\x00\x00\x02\x04\x05\xb4\x01\x03\x03\x05\x01\x01\x08\x0a\x2a\x9d\x05\x4c\x00\x00\x00\x00\x04\x02\x00\x00'

    tcp = TCP()
    tcp.pack()
    tcp.wireshark_print()

    newtcp = tcp.unpack(bindata)
    newtcp.wireshark_print()


## References

# https://tools.ietf.org/html/rfc793
# https://github.com/torvalds/linux/blob/master/include/net/tcp.h
# https://github.com/kbandla/dpkt/blob/master/dpkt/tcp.py
# https://stackoverflow.com/questions/10452855/tcp-sequence-number
# http://packetlife.net/blog/2010/jun/7/understanding-tcp-sequence-acknowledgment-numbers/
# https://tools.ietf.org/html/rfc6691
# http://unix.superglobalmegacorp.com/Net2/newsrc/netinet/tcp.h.html
# https://tools.ietf.org/html/rfc1071
# http://www.netfor2.com/tcpsum.htm