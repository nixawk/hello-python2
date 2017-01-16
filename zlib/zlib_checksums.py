#!/usr/bin/python
# -*- coding: utf-8 -*-

import zlib


data = open('/etc/passwd', 'r').read()
cksum = zlib.adler32(data)

print 'Adler32: %12d' % cksum
print '       : %12d' % zlib.adler32(data, cksum)

cksum = zlib.crc32(data)
print 'CRC-32 : %12d' % cksum
print '       : %12d' % zlib.crc32(data, cksum)
