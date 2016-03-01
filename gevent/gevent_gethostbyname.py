#!/usr/bin/python
# -*- coding: utf-8 -*-

import gevent
from gevent import socket

urls = ['www.google.com', 'www.example.com', 'www.python.org']
jobs = [gevent.spawn(socket.gethostbyname, url) for url in urls]
gevent.joinall(jobs,  timeout=2)
for job in jobs:
    print(job.value)


# After the jobs have been spawned, gevent.joinall waits for them to complete,
# allowing up to 2 seconds. The results are then collected by checking the value
# property. The gevent.socket.gethostbyname() function has the same interface as
# the standard socket.gethostbyname() but it does not block the whole interpreter
# and thus lets the other greenlets proceed with their requests unhindered.
