#!/usr/bin/python
# -*- coding: utf8 -*-


import zipimport


importer = zipimport.zipimporter('zipimport_example.zip')


for module_name in ['zipimport_find_module', 'not_there']:
    print(module_name, ':', importer.find_module(module_name))

# Given the full name of a module, find_module() will try to locate that module
# inside the ZIP archive.

# If the module is found, the zipimporter instance is returned.
# Otherwise, None is returned.
