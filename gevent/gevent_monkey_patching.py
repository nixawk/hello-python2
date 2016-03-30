#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
The example above used gevent.socket for socket operations. If the standard socket
module was used the example would have taken 3 times longer to complete because the
DNS requests would be sequential(serialized). Using the standard socket module inside
geeenlets makes gevent rather pointless, so what about existing modules and packages
that are built on top of socket (including the standard library modules like urllib)?

    from gevent import monkey; monkey.packet_socket()
    import urllib2  # it's usable from multiple greenlets now.
"""


"""
Beyond sockets

Of course, there are serval other parts of the standard library that can block the whole
interpreter and result in serialized behavior. gevent provides cooperative version of many
of those as well. They can be patched independently individual functions, but most programs
using monkey patching will want to patch the entire recommended set of modules using the
gevent.monkey.patch_all() function:

    from gevent import monkey; monkey.pacth_all()
    import subprocess  # it's usable from
"""

"""
Event Loop

Instead of blocking and waiting for socket perations to complete
(a technique known as polling)
"""
