#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
$  python2.7 impacket-stor_file.py
INFO:__main__:192.168.206.114/445 - establish a smb connection
INFO:__main__:192.168.206.114/445 - smb login: Administrator / p@ssw0rd
INFO:__main__:192.168.206.114/445 - upload data to remote file: C:\Windows\system32\hellosmb.txt
'''

# Please compare [impacket-readfile.pcap] with [impacket-retr_file.pcap]
# [impacket-retr_file.pcap] has an extra action: Trans2 Request, QUERY_FILE_INFO

from impacket import smb

import logging


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


data = 'A' * 300


def write_filecontent(len):
    global data

    answer, data = data[:len], data[len:]  # len: 65000
    return answer


if __name__ == '__main__':
    remote_name = "HELLOOOOOOOOOOO" # random string
    remote_host = "192.168.206.114"

    username = 'Administrator'
    password = 'p@ssw0rd'

    pth = r"C:\Windows\system32\hellosmb.txt"

    log.info('%s/445 - establish a smb connection', remote_host)
    smbclient = smb.SMB(remote_name, remote_host)

    log.info('%s/445 - smb login: %s / %s', remote_host, username, password)
    smbclient.login(username, password)

    drive, filename = pth.split(':')
    service = '%s$' % drive

    log.info('%s/445 - upload data to remote file: %s', remote_host, pth)
    smbclient.stor_file(service, filename, write_filecontent)


## References
# https://github.com/CoreSecurity/impacket/blob/master/impacket/smb.py#L3866