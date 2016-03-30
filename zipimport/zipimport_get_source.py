#!/usr/bin/python
# -*- coding: utf8 -*-

import zipimport


# As with the inspect module, it is possible to retrieve the source code for a
# module from the ZIP archive, if the archive includes the source. In the case
# of the example, only zipimport_get_source.py is added to zipimport_example.zip
# (the rest of the modules are just added as the .pyc files)

importer = zipimport.zipimporter('zipimport_example.zip')
for module_name in ['zipimport_get_code', 'zipimport_get_source']:
    source = importer.get_source(module_name)
    print('=' * 80)
    print(module_name)
    print('=' * 80)
    print(source)
    print()
