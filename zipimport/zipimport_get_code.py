#!/usr/bin/python
# -*- coding: utf8 -*-

import zipimport


importer = zipimport.zipimporter('zipimport_example.zip')
code = importer.get_code('zipimport_get_code')
print(code)
