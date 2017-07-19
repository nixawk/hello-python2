#!/usr/bin/python
# -*- coding: utf-8 -*-

# from impacket import smb  # no listShares() feature
from impacket.smbconnection import SMBConnection

import logging


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


if __name__ == '__main__':
    remote_name = "HELLOOOOOOOOOOO" # random string
    remote_host = "192.168.206.114"

    username = 'Administrator'
    password = 'p@ssw0rd'

    log.info('%s/445 - establish a smb connection', remote_host)
    smbclient = SMBConnection(remoteName=remote_name, remoteHost=remote_host)

    log.info('%s/445 - smb login: %s / %s', remote_host, username, password)
    smbclient.login(username, password)

    log.info('%s/445 - smb list shares', remote_host)
    for share in smbclient.listShares():
        shareName = share['shi1_netname']
        log.info('share name - %s', shareName)

    # from impacket import smb
    # smbclient = smb.SMB(remote_name, remote_host)
    # smbclient.login(username, password)
    # smbclient.list_path('C$')


## References
# # https://www.coresecurity.com/system/files/publications/2016/05/RicharteSolino_2006-impacketv0.9.6.0.pdf
