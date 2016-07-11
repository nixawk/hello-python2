#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


r = requests.get('https://github.com/', verify=True)
print(r.status_code)

"""
By default, verify is set to True. Option verify only applies to host certs.

You can also specify a local cert to use as client side certificate, as a
single file (containing the private key and the certificate) or as a tuple
of both file's path:

    >>> requests.get('https://github.com',
                     cert=('/path/server.crt', '/path/key'))

    >>> requests.get('https://github.com',
                     cert='/path/server.pem')


# CA Certificates

By default Requests bundles a set of root CAs that it trusts, sourced
from the Mozilla trust store:
    https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt).
However, these are only updated once for each Requests version.
This means that if you pin a Requests version your certificates
can become extremely out of date.

Frome Requests version 2.4.0 onwards, Requests will attempt to use
certificates from certifi if it is present on the system. This allows for
users to update their trusted certificates without having to change
the code that runs on their system.

For the sake of security we recommend upgrading certifi freqyently.
"""
