#!/usr/bin/python
# -*- coding: utf-8 -*-

import uuid


# The uuid module uses getnode() to retrieve the MAC value on a given system.
print(hex(uuid.getnode()))
