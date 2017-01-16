#!/usr/bin/python
# -*- coding: utf-8 -*-

import uuid


def show(msg, l):
    print msg
    for v in l:
        print '\t', v
    print

input_vaules = [
    'urn:uuid:f2f84497-b3bf-493a-bba9-7c68e6def80b',
    '{417a5ebb-01f7-4ed5-aeac-3d56cd5037b0}',
    '2115773a-5bf1-11dd-ab48-001ec200d9e0',
]

show('input_vaules', input_vaules)

uuids = [uuid.UUID(s) for s in input_vaules]
show('converted to uuids', uuids)

uuids.sort()
show('sorted', uuids)
