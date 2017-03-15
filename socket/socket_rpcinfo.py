#!/usr/bin/python
# -*- coding: utf-8 -

import socket
import struct
import time


class Service(object):
    def __init__(self):
        super(Service, self).__init__()

    def rpc_request(self):
        """Remote Procedure Call Request. If you want more, please use wireshark
        to capture (rpcinfo -p 192.168.1.100) packaets.
        """
        # Remote Procedure Call
        rpc_Fragment_header = 0x80000028
        rpc_XID = int(time.time())
        rpc_Message_Type = 0  # Call
        rpc_RPC_Version = 2
        rpc_Program = 100000  # Portmap
        rpc_Program_Version = 2
        rpc_Procedure = 4  # Dump
        rpc_Credentials_Flavor = 0  # AUTH_NULL
        rpc_Credentials_Length = 0
        rpc_Verifier_Flavor = 0  # AUTH_NULL
        rpc_Verifier_Length = 0

        # Portmap
        portmap_Program_Version = 2
        portmap_Procedure = 4 # Dump

        proto = struct.pack(
            # Remote Procedure Call
            '!LLLLLLLLLLLLL',
            rpc_Fragment_header,
            rpc_XID,
            rpc_Message_Type,
            rpc_RPC_Version,
            rpc_Program,
            rpc_Program_Version,
            rpc_Procedure,
            rpc_Credentials_Flavor,
            rpc_Credentials_Length,
            rpc_Verifier_Flavor,
            rpc_Verifier_Length,

            # portmap
            portmap_Program_Version,
            portmap_Procedure
        )

        return proto

    def parse_rpc_response(self, response):
        """parse Remote Procedure Call Reply.
        """
        rpc_map_entries = []

        if len(response) < 28:
            # Invalid rpc response
            return rpc_map_entries

        rpc = response[:28]
        (
            rpc_Fragment_header,
            rpc_XID,
            rpc_Message_Type,
            rpc_Reply_State,
            rpc_Verifier_Flavor,
            rpc_Verifier_Length,
            rpc_Accept_State
        ) = struct.unpack('!LLLLLLL', rpc)

        portmap = response[28:]
        if len(portmap) < 24:  # portmap_Value_Follows + one portmap_Map_entry
            return rpc_map_entries

        portmap_Value_Follows = portmap[0:4]
        portmap_Map_Entries = portmap[4:]

        portmap_Value_Follows = struct.unpack('!L', portmap_Value_Follows)
        portmap_Map_Entries = [
            portmap_Map_Entries[i:i+20]
            for i in range(0, len(portmap_Map_Entries), 20)
        ]

        for map_entry in portmap_Map_Entries:
            (
                program,
                version,
                protocol,
                port,
                value_follows
            ) = struct.unpack('!LLLLL', map_entry)

            if protocol == 0x06:
                protocol = '0x06,tcp'
            elif protocol == 0x11:
                protocol = '0x11,udp'
            else:
                protocol = '{},unknown'.format(protocol)

            _ = {
                'program': program, 'version': version,
                'protocol': protocol, 'port': port
            }
            if _ not in rpc_map_entries:
                rpc_map_entries.append(_)

        return rpc_map_entries

    def get_finger(self, host):
        banner = None

        buffersize=1024
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(4.0)
        try:
            client.connect((host, 111))
            client.send(self.rpc_request())
            rpc_response = client.recv(buffersize)
            print(self.parse_rpc_response(rpc_response))
        except Exception as err:
            print(err)
        finally:
            client.close()


if __name__ == '__main__':
    import sys

    rpc = Service()
    rpc.get_finger(sys.argv[1])
