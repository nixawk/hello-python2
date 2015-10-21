#!/usr/bin/python
# -*- coding: utf-8 -*-

import chardet


data = open('/etc/passwd').read()
print(chardet.detect(data))

# {'confidence': 1.0, 'encoding': 'ascii'}
