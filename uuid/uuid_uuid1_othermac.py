#!/usr/bin/python
# -*- coding: utf-8 -*-

import uuid


node1 = uuid.getnode()
print hex(node1), uuid.uuid1(node1)

node2 = 0x1e5274040e
print hex(node2), uuid.uuid1(node2)
