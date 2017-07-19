#!/usr/bin/python
# -*- coding: utf-8 -*-

# $ sudo pip install impacket

'''
$ python2.7 ipc.py 192.168.206.130 '' ''
INFO:__main__:target ip: 192.168.206.130
INFO:__main__:target os: 32 bit
INFO:__main__:   spoolss, True, {'ver_major': 5, 'ver_minor': 0, '_sec_trailer': 0, 'pduData': '\xb8\x10\xb8\x104\x17\x00\x00\x0e\x00\\pipe\\spoolss\x00\x01\x00\x00\x00\x00\x00\x00\x00\x04]\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00+\x10H`\x02\x00\x00\x00', 'frag_len': 68, 'pad': '', '_pad': 0, 'call_id': 1, 'auth_data': '', 'dataLen': 52, 'flags': 3, 'auth_dataLen': 0, 'representation': 16, 'sec_trailer': '', 'type': 12, 'auth_len': 0}
INFO:__main__:      samr, False, SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
INFO:__main__:  netlogon, False, SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
INFO:__main__:    lsarpc, False, SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
INFO:__main__:   browser, False, SMB SessionError: STATUS_OBJECT_NAME_NOT_FOUND(The object name is not found.)
'''

from impacket import smb
from impacket.dcerpc.v5 import transport
from impacket.uuid import uuidtup_to_bin
# from impacket.dcerpc.v5 import epm  # KNOWN_UUIDS / KNOWN_PROTOCOLS

import logging


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


class PIPEAUDIT(object):

    NDR64Syntax = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')
    NDRSyntax   = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

    MSPIPES = {
        'browser'  : ('6BFFD098-A112-3610-9833-012892020162','0.0'),  # [MS-BRWSA]: Common Internet File System (CIFS) Browser Auxiliary',
        'spoolss'  : ('12345678-1234-ABCD-EF00-0123456789AB','1.0'),  # [MS-RPRN]: Print System Remote Protocol,
        'netlogon' : ('12345678-1234-ABCD-EF00-01234567CFFB','1.0'),  # [MS-NRPC]: Netlogon Remote Protocol,
        'lsarpc'   : ('12345778-1234-ABCD-EF00-0123456789AB','0.0'),  # [MS-LSAT]: Local Security Authority (Translation Methods) Remote,
        'samr'     : ('12345778-1234-ABCD-EF00-0123456789AC','1.0'),  # [MS-SAMR]: Security Account Manager (SAM) Remote Protocol,
    }

    def __init__(self, remote_name, username='', password=''):

        self.remote_name = remote_name
        self.username = username
        self.password = password
        log.info('target ip: %s', self.remote_name)

    def decrpc_bind(self, pipe_name, pipe_uuid, transfer_syntax):
        '''Login remote smb host with username, password.
        Send NT Create AndX Request, Path: \pipe_name,
        and Check if pipe binds successfully or not.
        '''
        bindStatus, bindResponse = False, None

        try:
            rpctransport = transport.SMBTransport(
                self.remote_name, username=self.username, password=self.password,
                filename='\\'+pipe_name, smb_connection=False
            )
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            iface_uuid = uuidtup_to_bin(pipe_uuid)
            bindResponse = dce.bind(iface_uuid, transfer_syntax=transfer_syntax)
            if bindResponse:
                bindStatus = True
                bindResponse = bindResponse.fields

            dce.disconnect()
        except Exception as err:
            bindResponse = str(err)

        return bindStatus, bindResponse

    def is_64bit(self):
        '''Detect if target os is 64 bit.
        '''
        pipe_name = 'spoolss'
        pipe_uuid = ('12345678-1234-ABCD-EF00-0123456789AB', '1.0')

        bindStatus, bindResponse = self.decrpc_bind(pipe_name, pipe_uuid, self.NDR64Syntax)

        if bindStatus:
            log.info('target os: 64 bit')

        else:
            if 'transfer_syntaxes_not_supported' in bindResponse:
                log.info('target os: 32 bit')
            else:
                log.info('target os: unknown')

        return bindStatus

    def enumerate(self):
        '''Enumerate default pipe lists.
        '''

        transfer_syntax = self.NDR64Syntax if self.is_64bit() else self.NDRSyntax

        for pipe_name, pipe_uuid in self.MSPIPES.items():
            bindStatus, bindResponse = self.decrpc_bind(pipe_name, pipe_uuid, transfer_syntax)
            log.info("%10s, %s, %s", pipe_name, bindStatus, bindResponse)


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 4:
        log.info('[*] Usage: %s <ip> <username> <password>', sys.argv[0])
        sys.exit(0)

    ip = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]

    pipeaudit = PIPEAUDIT(ip, username, password)
    pipeaudit.enumerate()


## References
# https://msdn.microsoft.com/en-us/library/cc243845.aspx
# https://msdn.microsoft.com/en-us/library/cc243843.aspx
# https://blogs.msdn.microsoft.com/distributedservices/2010/02/04/list-of-uuids-for-msdtc-service-to-filter-traffic-on-the-firewall/
# https://kb.juniper.net/InfoCenter/index?page=content&id=KB12057
# https://technet.microsoft.com/en-us/library/cc738291(v=ws.10).aspx
# https://www.rfc-editor.org/rfc/rfc4122.txt
# https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/smb/pipe_dcerpc_auditor.rb
# https://github.com/CoreSecurity/impacket/blob/master/impacket/dcerpc/v5/epm.py
# https://www.blackhat.com/presentations/win-usa-04/bh-win-04-seki-up2.pdf
