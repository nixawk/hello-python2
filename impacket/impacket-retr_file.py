#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
$ python2.7 impacket-retr_file.py
INFO:__main__:192.168.206.114/445 - establish a smb connection
INFO:__main__:192.168.206.114/445 - smb login: Administrator / p@ssw0rd
INFO:__main__:192.168.206.114/445 - read remote file: C:\Windows\system32\winrm.cmd
INFO:__main__:@cscript //nologo "%~dpn0.vbs" %*
'''

# Please compare [impacket-readfile.pcap] with [impacket-retr_file.pcap]
# [impacket-retr_file.pcap] has an extra action: Trans2 Request, QUERY_FILE_INFO

from impacket import smb

import logging


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def print_filecontent(data):
    log.info(data)


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

    drive, filename = pth.split(':')
    service = '%s$' % drive

    log.info('%s/445 - read remote file: %s', remote_host, pth)
    smbclient.retr_file(service, filename, print_filecontent)


## References
# https://github.com/CoreSecurity/impacket/blob/master/impacket/smb.py#L3866