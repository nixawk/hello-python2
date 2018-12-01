# Copyright 2017 <Nixawk>. All Rights Reserved.
# Licensed to GNU under a Contributor Agreement.


"""IPv4, called INTERNET PROTOCOL. Please read https://tools.ietf.org/html/rfc791 for more protocol details."""


from __future__ import print_function
from __future__ import absolute_import

# from ctypes import *

import ctypes
import socket
import struct

# /*
#  * Definitions for internet protocol version 4.
#  * Per RFC 791, September 1981.
#  */

# +***************+
# Version:  4 bits
# +***************+

#   The Version field indicates the format of the internet header.  This
#   document describes version 4.

IP_VERSION = 0x04     # /* IPv4 */

# +***************+
# IHL:  4 bits
# +***************+

#   Internet Header Length is the length of the internet header in 32
#   bit words, and thus points to the beginning of the data.  Note that
#   the minimum value for a correct header is 5.

IP_IHL     = 0x05     # /* Internet Header Length, the minimum value for a correct header is 5. */

# +***************+
# Type of Service:  8 bits
# +***************+

#   The Type of Service provides an indication of the abstract
#   parameters of the quality of service desired.  These parameters are
#   to be used to guide the selection of the actual service parameters
#   when transmitting a datagram through a particular network.  Several
#   networks offer service precedence, which somehow treats high
#   precedence traffic as more important than other traffic (generally
#   by accepting only traffic above a certain precedence at time of high
#   load).  The major choice is a three way tradeoff between low-delay,
#   high-reliability, and high-throughput.

#     Bits 0-2:  Precedence.
#     Bit    3:  0 = Normal Delay,      1 = Low Delay.
#     Bits   4:  0 = Normal Throughput, 1 = High Throughput.
#     Bits   5:  0 = Normal Relibility, 1 = High Relibility.
#     Bit  6-7:  Reserved for Future Use.

#        0     1     2     3     4     5     6     7
#     +-----+-----+-----+-----+-----+-----+-----+-----+
#     |                 |     |     |     |     |     |
#     |   PRECEDENCE    |  D  |  T  |  R  |  0  |  0  |
#     |                 |     |     |     |     |     |
#     +-----+-----+-----+-----+-----+-----+-----+-----+

#       Precedence

#         111 - Network Control
#         110 - Internetwork Control
#         101 - CRITIC/ECP
#         100 - Flash Override
#         011 - Flash
#         010 - Immediate
#         001 - Priority
#         000 - Routine

#   The use of the Delay, Throughput, and Reliability indications may
#   increase the cost (in some sense) of the service.  In many networks
#   better performance for one of these parameters is coupled with worse
#   performance on another.  Except for very unusual cases at most two
#   of these three indications should be set.

#   The type of service is used to specify the treatment of the datagram
#   during its transmission through the internet system.  Example
#   mappings of the internet type of service to the actual service
#   provided on networks such as AUTODIN II, ARPANET, SATNET, and PRNET
#   is given in "Service Mappings"

#   The Network Control precedence designation is intended to be used
#   within a network only.  The actual use and control of that
#   designation is up to each network. The Internetwork Control
#   designation is intended for use by gateway control originators only.
#   If the actual use of these precedence designations is of concern to
#   a particular network, it is the responsibility of that network to
#   control the access to, and use of, those precedence designations.

IPTOS_LOWDELAY     = 0x10
IPTOS_THROUGHPUT   = 0x08
IPTOS_RELIABILITY  = 0x04


IPTOS_PREC_NETCONTROL      = 0xe0
IPTOS_PREC_INTERNETCONTROL = 0xc0
IPTOS_PREC_CRITIC_ECP      = 0xa0
IPTOS_PREC_FLASHOVERRIDE   = 0x80
IPTOS_PREC_FLASH           = 0x60
IPTOS_PREC_IMMEDIATE       = 0x40
IPTOS_PREC_PRIORITY        = 0x20
IPTOS_PREC_ROUTINE         = 0x10

# +***************+
# Total Length:  16 bits
# +***************+

#   Total Length is the length of the datagram, measured in octets,
#   including internet header and data.  This field allows the length of
#   a datagram to be up to 65,535 octets.  Such long datagrams are
#   impractical for most hosts and networks.  All hosts must be prepared
#   to accept datagrams of up to 576 octets (whether they arrive whole
#   or in fragments).  It is recommended that hosts only send datagrams
#   larger than 576 octets if they have assurance that the destination
#   is prepared to accept the larger datagrams.

#   The number 576 is selected to allow a reasonable sized data block to
#   be transmitted in addition to the required header information.  For
#   example, this size allows a data block of 512 octets plus 64 header
#   octets to fit in a datagram.  The maximal internet header is 60
#   octets, and a typical internet header is 20 octets, allowing a
#   margin for headers of higher level protocols.

IP_MAXPACKET   = 65535  # /* maximum packet size */

IP_HDR_LEN     = 0x14
IP_OPT_LEN     = 0x02
IP_OPT_LEN_MAX = 0x28
IP_HDR_LEN_MAX = IP_HDR_LEN + IP_OPT_LEN_MAX

# +***************+
# Identification:  16 bits
# +***************+

#   An identifying value assigned by the sender to aid in assembling the
#   fragments of a datagram.

# +***************+
# Flags:  3 bits
# +***************+

#   Various Control Flags.

#     Bit 0: reserved, must be zero
#     Bit 1: (DF) 0 = May Fragment,  1 = Don't Fragment.
#     Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments.

#         0   1   2
#       +---+---+---+
#       |   | D | M |
#       | 0 | F | F |
#       +---+---+---+

IP_RF = 0b000        # /* reserved            */
IP_DF = 0b010        # /* dont fragment flag  */
IP_MF = 0b001        # /* more fragments flag */

# +************************+
# Fragment Offset:  13 bits
# +************************+

#   This field indicates where in the datagram this fragment belongs.
#   The fragment offset is measured in units of 8 octets (64 bits).  The
#   first fragment has offset zero.

IP_FLAGBLANK = 0b000000000000 # /* Blank */

# +********************+
# Time to Live:  8 bits
# +********************+

#   This field indicates the maximum time the datagram is allowed to
#   remain in the internet system.  If this field contains the value
#   zero, then the datagram must be destroyed.  This field is modified
#   in internet header processing.  The time is measured in units of
#   seconds, but since every module that processes a datagram must
#   decrease the TTL by at least one even if it process the datagram in
#   less than a second, the TTL must be thought of only as an upper
#   bound on the time a datagram may exist.  The intention is to cause
#   undeliverable datagrams to be discarded, and to bound the maximum
#   datagram lifetime.

IP_TTL_DEFAULT = 64  # default ttl, RFC 1122, RFC 1340
IP_TTL_MAX     = 255 # maximum ttl

# +***************+
# Protocol:  8 bits
# +***************+

#   This field indicates the next level protocol used in the data
#   portion of the internet datagram.  The values for various protocols
#   are specified in "Assigned Numbers" 

IP_PROTO_IP         = 0  # dummy for IP
IP_PROTO_HOPOPTS    = IP_PROTO_IP  # IPv6 hop-by-hop options
IP_PROTO_ICMP       = 1  # ICMP
IP_PROTO_IGMP       = 2  # IGMP
IP_PROTO_GGP        = 3  # gateway-gateway protocol
IP_PROTO_IPIP       = 4  # IP in IP
IP_PROTO_ST         = 5  # ST datagram mode
IP_PROTO_TCP        = 6  # TCP
IP_PROTO_CBT        = 7  # CBT
IP_PROTO_EGP        = 8  # exterior gateway protocol
IP_PROTO_IGP        = 9  # interior gateway protocol
IP_PROTO_BBNRCC     = 10  # BBN RCC monitoring
IP_PROTO_NVP        = 11  # Network Voice Protocol
IP_PROTO_PUP        = 12  # PARC universal packet
IP_PROTO_ARGUS      = 13  # ARGUS
IP_PROTO_EMCON      = 14  # EMCON
IP_PROTO_XNET       = 15  # Cross Net Debugger
IP_PROTO_CHAOS      = 16  # Chaos
IP_PROTO_UDP        = 17  # UDP
IP_PROTO_MUX        = 18  # multiplexing
IP_PROTO_DCNMEAS    = 19  # DCN measurement
IP_PROTO_HMP        = 20  # Host Monitoring Protocol
IP_PROTO_PRM        = 21  # Packet Radio Measurement
IP_PROTO_IDP        = 22  # Xerox NS IDP
IP_PROTO_TRUNK1     = 23  # Trunk-1
IP_PROTO_TRUNK2     = 24  # Trunk-2
IP_PROTO_LEAF1      = 25  # Leaf-1
IP_PROTO_LEAF2      = 26  # Leaf-2
IP_PROTO_RDP        = 27  # "Reliable Datagram" proto
IP_PROTO_IRTP       = 28  # Inet Reliable Transaction
IP_PROTO_TP         = 29  # ISO TP class 4
IP_PROTO_NETBLT     = 30  # Bulk Data Transfer
IP_PROTO_MFPNSP     = 31  # MFE Network Services
IP_PROTO_MERITINP   = 32  # Merit Internodal Protocol
IP_PROTO_SEP        = 33  # Sequential Exchange proto
IP_PROTO_3PC        = 34  # Third Party Connect proto
IP_PROTO_IDPR       = 35  # Interdomain Policy Route
IP_PROTO_XTP        = 36  # Xpress Transfer Protocol
IP_PROTO_DDP        = 37  # Datagram Delivery Proto
IP_PROTO_CMTP       = 38  # IDPR Ctrl Message Trans
IP_PROTO_TPPP       = 39  # TP++ Transport Protocol
IP_PROTO_IL         = 40  # IL Transport Protocol
IP_PROTO_IP6        = 41  # IPv6
IP_PROTO_SDRP       = 42  # Source Demand Routing
IP_PROTO_ROUTING    = 43  # IPv6 routing header
IP_PROTO_FRAGMENT   = 44  # IPv6 fragmentation header
IP_PROTO_RSVP       = 46  # Reservation protocol
IP_PROTO_GRE        = 47  # General Routing Encap
IP_PROTO_MHRP       = 48  # Mobile Host Routing
IP_PROTO_ENA        = 49  # ENA
IP_PROTO_ESP        = 50  # Encap Security Payload
IP_PROTO_AH         = 51  # Authentication Header
IP_PROTO_INLSP      = 52  # Integated Net Layer Sec
IP_PROTO_SWIPE      = 53  # SWIPE
IP_PROTO_NARP       = 54  # NBMA Address Resolution
IP_PROTO_MOBILE     = 55  # Mobile IP, RFC 2004
IP_PROTO_TLSP       = 56  # Transport Layer Security
IP_PROTO_SKIP       = 57  # SKIP
IP_PROTO_ICMP6      = 58  # ICMP for IPv6
IP_PROTO_NONE       = 59  # IPv6 no next header
IP_PROTO_DSTOPTS    = 60  # IPv6 destination options
IP_PROTO_ANYHOST    = 61  # any host internal proto
IP_PROTO_CFTP       = 62  # CFTP
IP_PROTO_ANYNET     = 63  # any local network
IP_PROTO_EXPAK      = 64  # SATNET and Backroom EXPAK
IP_PROTO_KRYPTOLAN  = 65  # Kryptolan
IP_PROTO_RVD        = 66  # MIT Remote Virtual Disk
IP_PROTO_IPPC       = 67  # Inet Pluribus Packet Core
IP_PROTO_DISTFS     = 68  # any distributed fs
IP_PROTO_SATMON     = 69  # SATNET Monitoring
IP_PROTO_VISA       = 70  # VISA Protocol
IP_PROTO_IPCV       = 71  # Inet Packet Core Utility
IP_PROTO_CPNX       = 72  # Comp Proto Net Executive
IP_PROTO_CPHB       = 73  # Comp Protocol Heart Beat
IP_PROTO_WSN        = 74  # Wang Span Network
IP_PROTO_PVP        = 75  # Packet Video Protocol
IP_PROTO_BRSATMON   = 76  # Backroom SATNET Monitor
IP_PROTO_SUNND      = 77  # SUN ND Protocol
IP_PROTO_WBMON      = 78  # WIDEBAND Monitoring
IP_PROTO_WBEXPAK    = 79  # WIDEBAND EXPAK
IP_PROTO_EON        = 80  # ISO CNLP
IP_PROTO_VMTP       = 81  # Versatile Msg Transport
IP_PROTO_SVMTP      = 82  # Secure VMTP
IP_PROTO_VINES      = 83  # VINES
IP_PROTO_TTP        = 84  # TTP
IP_PROTO_NSFIGP     = 85  # NSFNET-IGP
IP_PROTO_DGP        = 86  # Dissimilar Gateway Proto
IP_PROTO_TCF        = 87  # TCF
IP_PROTO_EIGRP      = 88  # EIGRP
IP_PROTO_OSPF       = 89  # Open Shortest Path First
IP_PROTO_SPRITERPC  = 90  # Sprite RPC Protocol
IP_PROTO_LARP       = 91  # Locus Address Resolution
IP_PROTO_MTP        = 92  # Multicast Transport Proto
IP_PROTO_AX25       = 93  # AX.25 Frames
IP_PROTO_IPIPENCAP  = 94  # yet-another IP encap
IP_PROTO_MICP       = 95  # Mobile Internet Ctrl
IP_PROTO_SCCSP      = 96  # Semaphore Comm Sec Proto
IP_PROTO_ETHERIP    = 97  # Ethernet in IPv4
IP_PROTO_ENCAP      = 98  # encapsulation header
IP_PROTO_ANYENC     = 99  # private encryption scheme
IP_PROTO_GMTP       = 100  # GMTP
IP_PROTO_IFMP       = 101  # Ipsilon Flow Mgmt Proto
IP_PROTO_PNNI       = 102  # PNNI over IP
IP_PROTO_PIM        = 103  # Protocol Indep Multicast
IP_PROTO_ARIS       = 104  # ARIS
IP_PROTO_SCPS       = 105  # SCPS
IP_PROTO_QNX        = 106  # QNX
IP_PROTO_AN         = 107  # Active Networks
IP_PROTO_IPCOMP     = 108  # IP Payload Compression
IP_PROTO_SNP        = 109  # Sitara Networks Protocol
IP_PROTO_COMPAQPEER = 110  # Compaq Peer Protocol
IP_PROTO_IPXIP      = 111  # IPX in IP
IP_PROTO_VRRP       = 112  # Virtual Router Redundancy
IP_PROTO_PGM        = 113  # PGM Reliable Transport
IP_PROTO_ANY0HOP    = 114  # 0-hop protocol
IP_PROTO_L2TP       = 115  # Layer 2 Tunneling Proto
IP_PROTO_DDX        = 116  # D-II Data Exchange (DDX)
IP_PROTO_IATP       = 117  # Interactive Agent Xfer
IP_PROTO_STP        = 118  # Schedule Transfer Proto
IP_PROTO_SRP        = 119  # SpectraLink Radio Proto
IP_PROTO_UTI        = 120  # UTI
IP_PROTO_SMP        = 121  # Simple Message Protocol
IP_PROTO_SM         = 122  # SM
IP_PROTO_PTP        = 123  # Performance Transparency
IP_PROTO_ISIS       = 124  # ISIS over IPv4
IP_PROTO_FIRE       = 125  # FIRE
IP_PROTO_CRTP       = 126  # Combat Radio Transport
IP_PROTO_CRUDP      = 127  # Combat Radio UDP
IP_PROTO_SSCOPMCE   = 128  # SSCOPMCE
IP_PROTO_IPLT       = 129  # IPLT
IP_PROTO_SPS        = 130  # Secure Packet Shield
IP_PROTO_PIPE       = 131  # Private IP Encap in IP
IP_PROTO_SCTP       = 132  # Stream Ctrl Transmission
IP_PROTO_FC         = 133  # Fibre Channel
IP_PROTO_RSVPIGN    = 134  # RSVP-E2E-IGNORE
IP_PROTO_RAW        = 255  # Raw IP packets
IP_PROTO_RESERVED   = IP_PROTO_RAW  # Reserved
IP_PROTO_MAX        = 255

# +************************+
# Header Checksum:  16 bits
# +************************+

#   A checksum on the header only.  Since some header fields change
#   (e.g., time to live), this is recomputed and verified at each point
#   that the internet header is processed.

#   The checksum algorithm is:

#     The checksum field is the 16 bit one's complement of the one's
#     complement sum of all 16 bit words in the header.  For purposes of
#     computing the checksum, the value of the checksum field is zero.

#   This is a simple to compute checksum and experimental evidence
#   indicates it is adequate, but it is provisional and may be replaced
#   by a CRC procedure, depending on further experience.

# +***********************+
# Source Address:  32 bits
# +***********************+

# +****************************+
# Destination Address:  32 bits
# +****************************+

IP_ADDR_LEN         = 0x04   # /* src/dest ip address */
IP_ADDR_BITS        = 0x20

IP_ADDR_ANY         = 0x00000000    # 0.0.0.0
IP_ADDR_BROADCAST   = 0xFFFFFFFF    # 255.255.255.255
IP_ADDR_LOOPBACK    = 0x7F000001    # 127.0.0.1
IP_ADDR_MCAST_ALL   = 0xE0000001    # 224.0.0.1
IP_ADDR_MCAST_LOCAL = 0xe00000FF    # 224.0.0.255

# BigEndianStructure
# ctypes._endian.BigEndianStructure

# LittleEndianStructure
# _ctypes.Structure

# Structure
# _ctypes.Structure


class IP(ctypes.BigEndianStructure):

    '''
    # Internet Header Format

    #   A summary of the contents of the internet header follows:


    #     0                   1                   2                   3
    #     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #    |Version|  IHL  |Type of Service|          Total Length         |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #    |         Identification        |Flags|      Fragment Offset    |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #    |  Time to Live |    Protocol   |         Header Checksum       |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #    |                       Source Address                          |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #    |                    Destination Address                        |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #    |                    Options                    |    Padding    |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    >>> from protocols import ip
    >>> ipobj = ip.IP()
    >>> ipobj.raw
    b'E\x10\x00\x14\x00\x00\x00\x00@\x00\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01'
    >>> ipobj.checksum()
    31960

    '''

    # Internet Protocol Version 4, 20 bytes

    _align_  = 1  # Page Alignment (64 bit is different with 32 bit)

    _fields_ = [

        # BigEndianStructure:    ip_v + ip_hl
        # LittleEndianStructure: ip_hl + ip_v

        ('ip_v',    ctypes.c_ubyte,   4),       # /* version */
        ('ip_hl',   ctypes.c_ubyte,   4),       # /* header length */

        ('ip_tos',  ctypes.c_ubyte),            # /* type of service */
        ('ip_len',  ctypes.c_short),            # /* total length */
        ('ip_id',   ctypes.c_ushort),           # /* identification */
        ('ip_flag', ctypes.c_short,   3),       # /* Various Control Flags. */
        ('ip_off',  ctypes.c_short,  13),       # /* fragment offset field */
        ('ip_ttl',  ctypes.c_ubyte),            # /* time to live */
        ('ip_p',    ctypes.c_ubyte),            # /* protocol */
        ('ip_sum',  ctypes.c_ushort),           # /* checksum */
        ('ip_src',  ctypes.c_uint32),           # /* source address */
        ('ip_dst',  ctypes.c_uint32)            # /* dest address */
    ]

    # def __new__(self, buffer=b''):
    #     return self.from_buffer_copy(buffer)

    def __init__(self, 
            ip_v    = IP_VERSION,         # Version:  4 bits
            ip_hl   = IP_IHL,             # IHL:  4 bits
            ip_tos  = IPTOS_PREC_ROUTINE, # Type of Service:  8 bits
            ip_len  = IP_HDR_LEN,         # Total Length:  16 bits
            ip_id   = 0,                  # Identification:  16 bits
            ip_flag = IP_RF,              # Flags:  3 bits
            ip_off  = IP_FLAGBLANK,       # Fragment Offset:  13 bits
            ip_ttl  = IP_TTL_DEFAULT,     # Time to Live:  8 bits
            ip_p    = IP_PROTO_IP,        # Protocol:  8 bits
            ip_sum  = 0,                  # Header Checksum:  16 bits
            ip_src  = IP_ADDR_LOOPBACK,   # Source Address:  32 bits
            ip_dst  = IP_ADDR_LOOPBACK    # Destination Address:  32 bits
        ):

        super(IP, self).__init__(
            ip_v, ip_hl, ip_tos, ip_len, ip_id,
            ip_flag, ip_off, ip_ttl, ip_p, ip_sum, ip_src, ip_dst
        )

    def pack(self):
        '''pack an ip object into binary data.'''
        return ctypes.string_at(ctypes.addressof(self), ctypes.sizeof(self))

    def unpack(self, buf):
        '''unpack binary buf into an ip object.'''

        if not isinstance(buf, bytes):
            raise Exception('unpack buffer must be a byte string.')

        cstring = ctypes.create_string_buffer(buf)
        ctype_instance = ctypes.cast(ctypes.pointer(cstring), ctypes.POINTER(IP)).contents

        return ctype_instance

    def inet_ntoa(self, intaddr):
        '''translate integer into str ip address.'''
        return socket.inet_ntoa(struct.pack("!I", intaddr))  

    def inet_aton(self, straddr):
        '''translate str ip addess into integer.'''
        return struct.unpack("!I", socket.inet_aton(straddr))[0]

    def wireshark_print(self, buf=None):
        '''output binary packet as what wireshark prints.'''
        buf = buf if buf else self.raw
        ipinstance = self.unpack(buf)

        print("Internet Protocol Version %s, Src: %s, Dst: %s" % (self.ip_v, self.inet_ntoa(self.ip_src), self.inet_ntoa(self.ip_dst)))
        print("  %s .... = Version: %s" % (bin(self.ip_v).replace('0b', '').rjust(4, '0'), self.ip_v))
        print("  .... %s = Header Length: 20 bytes (%s)" % (bin(self.ip_hl).replace('0b', '').rjust(4, '0'), self.ip_hl))
        print("Differentiated Services Field: 0x%02x" % self.ip_tos)
        print("Total Length: %s" % self.ip_len)
        print("Identifiaction: 0x%04x (%d)" % (self.ip_id, self.ip_id))
        print("Flags: 0x%02x" % self.ip_flag)
        print("Fragment offset: %d" % self.ip_off)
        print("Time to live: %d" % self.ip_ttl)
        print("Protocol: %s" % self.ip_p)
        print("Header checksum: 0x%04x" % self.ip_sum)
        print("Source: %s" % self.inet_ntoa(self.ip_src))
        print("Destination: %s" % self.inet_ntoa(self.ip_dst))

    def checksum(self, msg=None):
        '''sum ip protocol checksum'''

        # https://github.com/emamirazavi/python3-ping/blob/master/ping.py#L246
        # https://stackoverflow.com/questions/3949726/calculate-ip-checksum-in-python

        self.ip_sum = 0                  # Initialize ip_sum to zero (First)
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
        self.ip_sum = s
        return s

    @property
    def raw(self):
        '''ip raw data.'''
        return self.pack()

    def __str__(self):
        '''return packet binary as a string.'''
        return str(self.pack())

    def __len__(self):
        '''return packet length.'''
        return ctypes.sizeof(self)


if __name__ == '__main__':
    # Translate Binary Data into IP Object
    bindata = b'\x45\x00\x00\x40\x48\x22\x40\x00\x40\x06\xd4\xd0\xc0\xa8\xce\x01\xc0\xa8\xce\x72'
    ip = IP().unpack(bindata)

    # Print packet information in wireshark format
    ip.wireshark_print(bindata)

    # Print IP Raw data
    # print(ip.raw)

    # Calculate IP checksum
    # print(ip.checksum())

    # If python2: (b'aaa' == 'aaa') == True
    # If python3: (b'aaa' == 'aaa') == False

    assert(bindata == ip.raw), Exception('parse ip bindata error.')


## References

# https://tools.ietf.org/html/rfc791
# https://docs.python.org/3/library/ctypes.html
# https://github.com/torvalds/linux/tree/master/include/linux
# https://stackoverflow.com/questions/14771150/python-ctypes-pragma-pack-for-byte-aligned-read
# https://stackoverflow.com/questions/18536182/parsing-binary-data-into-ctypes-structure-object-via-readinto
# https://codexample.org/questions/222055/how-to-pack-and-unpack-using-ctypes-structure-str.c
# http://unix.superglobalmegacorp.com/Net2/newsrc/netinet/ip.h.html
# https://stackoverflow.com/questions/7946519/default-values-in-a-ctypes-structure
# https://stackoverflow.com/questions/5619685/conversion-from-ip-string-to-integer-and-backward-in-python
# https://github.com/kbandla/dpkt/blob/master/dpkt/ip.py
# https://github.com/emamirazavi/python3-ping/blob/master/ping.py#L246