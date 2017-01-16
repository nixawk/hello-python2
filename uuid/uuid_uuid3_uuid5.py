#!/usr/bin/python
# -*- coding: utf-8 -*-


import uuid


# The UUID value for a given name in namespace is always the same, no matter
# when it is calculated. Values for the same name in different namespaces are different.

hostnames = ['www.exploit-db.com', 'www.offensive-security.com']
for name in hostnames:
    print name
    print '\tMD5    :', uuid.uuid3(uuid.NAMESPACE_DNS, name)
    print '\tSHA-1  :', uuid.uuid3(uuid.NAMESPACE_DNS, name)

urls = ['https://search.yahoo.com/', 'https://www.google.com/']
for url in urls:
    print url
    print '\tMD5    :', uuid.uuid3(uuid.NAMESPACE_URL, url)
    print '\tSHA-1  :', uuid.uuid5(uuid.NAMESPACE_URL, url)
