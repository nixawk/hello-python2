#!/usr/bin/python
# -*- coding: utf-8 -*-

import zlib


data = open('/etc/passwd', 'rt').read()
compressed = zlib.compress(data)
combined = compressed + data

decompressor = zlib.decompressobj()
decompressed = decompressor.decompress(combined)

print('Decompressed matches data:', decompressed == data)
print('Unused data matches data:', decompressor.unused_data == data)
