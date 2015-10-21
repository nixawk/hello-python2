#!/usr/bin/python
# -*- coding: utf-8 -*-

from distutils.spawn import find_executable


print("[*] command: id - %s" % find_executable('id'))

# [*] command: id - /usr/bin/id
