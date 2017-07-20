#!/usr/bin/python
# -*- coding: utf-8 -*-

# Author: Nixawk
# $ sudo pip install impacket

# [client -> server] DCERPC: Bind call_id: 1, EPMv4 V3.0 (32bit NDR)
# [server -> client] DCERPC: Bind ack

# [client -> server] EPM:    Lookup request
# [server -> client] DCERPC: Response
# [server -> client] DCERPC: Response
# [server -> client] DCERPC: Response
# [server -> client] DCERPC: Response
# [server -> client] EPM:    Lookup response

'''
$ python2.7 impacket-rpcdump.py 192.168.206.114 135
{'APPLICATION': 'wininit.exe',
 'IP': '192.168.206.114',
 'NDR_UUID': ('8A885D04-1CEB-11C9-9FE8-08002B104860', 2.0),
 'NETBIOS': [],
 'PIPE': [],
 'PROTOCOL': '[MS-RSP]: Remote Shutdown Protocol',
 'UUID': ('D95AFE70-A6D5-4259-822E-2C84DA1DDB0D', 1.0)}
{'APPLICATION': 'wininit.exe',
 'IP': '',
 'NDR_UUID': ('8A885D04-1CEB-11C9-9FE8-08002B104860', 2.0),
 'NETBIOS': [],
 'PIPE': ['WindowsShutdown\x00'],
 'PROTOCOL': '[MS-RSP]: Remote Shutdown Protocol',
 'UUID': ('D95AFE70-A6D5-4259-822E-2C84DA1DDB0D', 1.0)}
{'APPLICATION': 'wininit.exe',
 'IP': '',
 'NDR_UUID': ('8A885D04-1CEB-11C9-9FE8-08002B104860', 2.0),
 'NETBIOS': ['\\\\JOHN\x00'],
 'PIPE': ['\\PIPE\\InitShutdown\x00'],
 'PROTOCOL': '[MS-RSP]: Remote Shutdown Protocol',
 'UUID': ('D95AFE70-A6D5-4259-822E-2C84DA1DDB0D', 1.0)}
{'APPLICATION': 'wininit.exe',
 'IP': '',
 'NDR_UUID': ('8A885D04-1CEB-11C9-9FE8-08002B104860', 2.0),
 'NETBIOS': [],
 'PIPE': ['WMsgKRpc0AC700\x00'],
 'PROTOCOL': '[MS-RSP]: Remote Shutdown Protocol',
 'UUID': ('D95AFE70-A6D5-4259-822E-2C84DA1DDB0D', 1.0)}
{'APPLICATION': 'winlogon.exe',
 'IP': '',
 'NDR_UUID': ('8A885D04-1CEB-11C9-9FE8-08002B104860', 2.0),
 'NETBIOS': [],
 'PIPE': ['WindowsShutdown\x00'],
 'PROTOCOL': 'N/A',
 'UUID': ('76F226C3-EC14-4325-8A99-6A46348418AF', 1.0)}

......
......

'''

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import epm
from impacket import uuid

import socket


PROTO_ID_OSI_OID        = 0x00
PROTO_ID_DNA_SESSCTL    = 0x02
PROTO_ID_DNA_SESSCTL_V3 = 0x03
PROTO_ID_DNA_NSP        = 0x04
PROTO_ID_OSI_TP4        = 0x05
PROTO_ID_OSI_CLNS       = 0x06
PROTO_ID_TCP            = 0x07
PROTO_ID_UDP            = 0x08
PROTO_ID_IP             = 0x09
PROTO_ID_RPC_CL         = 0x0a
PROTO_ID_RPC_CO         = 0x0b
PROTO_ID_SPX            = 0x0c    # /* from DCOM spec (is this correct?) */
PROTO_ID_UUID           = 0x0d
PROTO_ID_IPX            = 0x0e    # /* from DCOM spec (is this correct?) */
PROTO_ID_NAMED_PIPES    = 0x0f
PROTO_ID_NAMED_PIPES_2  = 0x10
PROTO_ID_NETBIOS        = 0x11
PROTO_ID_NETBEUI        = 0x12
PROTO_ID_NETWARE_SPX    = 0x13
PROTO_ID_NETWARE_IPX    = 0x14
PROTO_ID_ATALK_STREAM   = 0x16
PROTO_ID_ATALK_DATAGRAM = 0x17
PROTO_ID_ATALK          = 0x18
PROTO_ID_NETBIOS_2      = 0x19
PROTO_ID_VINES_SPP      = 0x1a
PROTO_ID_VINES_IPC      = 0x1b
PROTO_ID_STREETTALK     = 0x1c
PROTO_ID_HTTP           = 0x1f
PROTO_ID_UNIX_DOMAIN    = 0x20
PROTO_ID_NULL           = 0x21
PROTO_ID_NETBIOS_3      = 0x22


NDR64_UUID = '71710533-BEBA-4937-8319-B5DBEF9CCC36'
NDR64_VER  = '1.0'

NDR32_UUID = '8A885D04-1CEB-11C9-9FE8-08002B104860'
NDR32_VER  = '2.0'


def send_EPM_Lookup_request(remote_host, remote_port):

    protocols = {
        135: 'ncacn_ip_tcp:%s' % remote_host,
        139: 'ncacn_np:%s[\pipe\epmapper]' % remote_host,
        445: 'ncacn_np:%s[\pipe\epmapper]' % remote_host
    }

    bindstr = protocols[remote_port]

    rpctransport = transport.DCERPCTransportFactory(bindstr)
    rpctransport.set_dport(remote_port)
    
    # rpctransport.setRemoteHost(remote_host)

    dce = rpctransport.get_dce_rpc()
    dce.connect()

    entries = epm.hept_lookup(None, dce=dce)

    dce.disconnect()

    return entries


def parse_EPM_Entries(entries):

    endpoints = {}

    for entry in entries:

        entry_Object         = entry.get('object')
        entry_Tower_pointer  = entry.get('tower')
        entry_Annotation     = entry.get('annotation')

        entry_ObjectStr      = uuid.bin_to_string(entry_Object)

        entry_Floors         = (entry_Tower_pointer.fields).get('Floors')
        entry_NumberOfFloors = (entry_Tower_pointer.fields).get('NumberOfFloors')

        entry_Tower_Floor_Info = parse_EPM_Entry_Floors(entry_Floors)

        from pprint import pprint

        pprint(entry_Tower_Floor_Info)


def parse_EPM_Entry_Floors(entry_Floors):

    entry_Tower_Floor_Info = {
        'UUID'        : [],
        'NDR_UUID'    : [],
        'IP'          : '',
        'PIPE'   : [],
        'NETBIOS'     : [],
        'APPLICATION' : '',
        'PROTOCOL'    : ''
    }

    for floor in entry_Floors:

        protocol = floor.getData()[2]
        protocol = int(ord(protocol))

        if protocol == PROTO_ID_UUID:
            floor_fields = floor.fields

            # import ipdb; ipdb.set_trace()

            floor_MajorVersion     = floor_fields.get('MajorVersion')
            floor_MinorVersion     = floor_fields.get('MinorVersion')
            floor_InterfaceIdent   = floor_fields.get('InterfaceIdent')
            floor_RHSByteCount     = floor_fields.get('RHSByteCount')

            # different UUID definition in EPMFloor Structure from (impacket/dcerpc/v5/epm.py)
            floor_InterfaceUUID    = floor_fields.get('InterfaceUUID')
            floor_DataRepUuid      = floor_fields.get('DataRepUuid')

            floor_LHSByteCount     = floor_fields.get('LHSByteCount')

            floor_UUID             = floor_InterfaceUUID if floor_InterfaceUUID else floor_DataRepUuid
            floor_UUIDStr          = uuid.bin_to_string(floor_UUID)

            floor_Version          = float("%s.%s" % (floor_MajorVersion, floor_MinorVersion))

            if not floor_UUIDStr: continue

            if floor_UUIDStr.upper() in (NDR64_UUID, NDR32_UUID):
                entry_Tower_Floor_Info['NDR_UUID'] = (floor_UUIDStr, floor_Version)
            else:
                entry_Tower_Floor_Info['UUID'] = (floor_UUIDStr, floor_Version)

        elif protocol == PROTO_ID_IP:
            floor_fields = floor.fields

            entry_Tower_Floor_Info['IP'] = socket.inet_ntoa(floor_fields['RelatedData'])

        elif protocol in (PROTO_ID_NAMED_PIPES, PROTO_ID_NAMED_PIPES_2):

            floor_fields = floor.fields
            named_pipe = floor_fields.get('RelatedData')

            if not named_pipe: continue
            if named_pipe not in entry_Tower_Floor_Info['PIPE']:
                entry_Tower_Floor_Info['PIPE'].append(named_pipe)

        elif protocol == PROTO_ID_NETBIOS:
            floor_fields = floor.fields
            netbios_name = floor_fields.get('RelatedData')

            if not netbios_name: continue
            if netbios_name not in entry_Tower_Floor_Info['NETBIOS']:
                entry_Tower_Floor_Info['NETBIOS'].append(netbios_name)

    entry_UUID = entry_Tower_Floor_Info['UUID']
    if entry_UUID:

        # Add APPLICATION Info into entry_Tower_Floor_Info
        _uuid, _ver = entry_UUID

        key = uuid.uuidtup_to_bin(uuid.string_to_uuidtup(_uuid))[:18]
        application = epm.KNOWN_UUIDS[key] if key in epm.KNOWN_UUIDS else 'N/A'

        entry_Tower_Floor_Info['APPLICATION'] = application

        # Add POTOCOL Info into entry_Tower_Floor_Info
        key = _uuid[:36]
        protocol = epm.KNOWN_PROTOCOLS[key] if key in epm.KNOWN_PROTOCOLS else 'N/A'

        entry_Tower_Floor_Info['PROTOCOL'] = protocol

    return entry_Tower_Floor_Info


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 3:
        print("[*] Usage: python %s <host> <port, ex: 135, 139, 445>")
        sys.exit(0)

    host = sys.argv[1]
    port = sys.argv[2]

    entries = send_EPM_Lookup_request(host, int(port))
    parse_EPM_Entries(entries)


## References
# https://github.com/CoreSecurity/impacket/blob/master/examples/rpcdump.py
# https://github.com/boundary/wireshark/blob/master/epan/dissectors/packet-dcerpc-epm.c