#!/usr/bin/python
# -*- coding: utf-8 -*-

import uuid


# To generate a UUID for a given host, identified by its MAC address,
# use the uuid1() function.
u = uuid.uuid1()

print u
print type(u)
print 'bytes   :', repr(u.bytes)
print 'hex     :', u.hex
print 'int     :', u.int
print 'urn     :', u.urn
print 'variant :', u.variant
print 'version :', u.version
print 'fields  :', u.fields
print '\ttime_low             :', u.time_low
print '\ttime_mid             :', u.time_mid
print '\ttime_hi_version      :', u.time_hi_version
print '\tclock_seq_hi_variant :', u.clock_seq_hi_variant
print '\tclock_seq_low        :', u.clock_seq_low
print '\tnode                 :', u.node
print '\ttime                 :', u.time
print '\tclock_seq            :', u.clock_seq
