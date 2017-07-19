#!/usr/bin/python
# -*- coding: utf-8 -*-

# Lab Environment:

# impacket (0.9.15)
# Windows 7 Ultimate - Microsoft Windows [Version 6.1.7601]


'''
$ python2.7 impacket-readfile.py
INFO:__main__:192.168.206.114/445 - establish a smb connection
INFO:__main__:192.168.206.114/445 - smb login: Administrator / password
INFO:__main__:192.168.206.114/445 - read remote file: C:\Windows\system32\winrm.cmd
INFO:__main__:192.168.206.114/445 - file contents: @cscript //nologo "%~dpn0.vbs" %*

INFO:__main__:192.168.206.114/445 - close smb connection
'''

from impacket import smb

import logging


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


if __name__ == '__main__':
    remote_name = "HELLOOOOOOOOOOO" # random string
    remote_host = "192.168.206.114"

    username = 'Administrator'
    password = 'p@ssw0rd'

    pth = r"C:\Windows\system32\winrm.cmd"

    log.info('%s/445 - establish a smb connection', remote_host)
    smbclient = smb.SMB(remote_name, remote_host)

    log.info('%s/445 - smb login: %s / %s', remote_host, username, password)
    smbclient.login(username, password)

    log.info('%s/445 - read remote file: %s', remote_host, pth)

    drive, pth = pth.split(':')

    ipc = r'\\%s\%s$' % (remote_name, drive)
    tid = smbclient.tree_connect_andx(ipc)

    (
        fid,
        fileAttributes,
        lastWriten,
        fileSize,
        grantedAccess,
        fileType,
        ipcState,
        action,
        serverFid
    ) = smbclient.open_andx(tid, pth, smb.SMB_O_OPEN, smb.SMB_ACCESS_READ) 

    log.info("%s/445 - file contents: %s", remote_host, smbclient.read_andx(tid, fid))
    log.info("%s/445 - close smb connection", remote_host)
    smbclient.close(tid, fid)


# https://www.coresecurity.com/system/files/publications/2016/05/RicharteSolino_2006-impacketv0.9.6.0.pdf