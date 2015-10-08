#!/usr/bin/env python
# -*- coding: utf-8 -*-

# From recon-ng/recon/core/framework.py
import re


def is_hash(hashstring):
    hashdict = [
        {'pattern': '^[a-fA-F0-9]{32}$', 'type': 'MD5'},
        {'pattern': '^[a-fA-F0-9]{16}$', 'type': 'MySQL'},
        {'pattern': '^\*[a-fA-F0-9]{40}$', 'type': 'MySQL5'},
        {'pattern': '^[a-fA-F0-9]{40}$', 'type': 'SHA1'},
        {'pattern': '^[a-fA-F0-9]{56}$', 'type': 'SHA224'},
        {'pattern': '^[a-fA-F0-9]{64}$', 'type': 'SHA256'},
        {'pattern': '^[a-fA-F0-9]{96}$', 'type': 'SHA384'},
        {'pattern': '^[a-fA-F0-9]{128}$', 'type': 'SHA512'},
        {'pattern': '^\$[PH]{1}\$.{31}$', 'type': 'phpass'},
        {'pattern': '^\$2[ya]?\$.{56}$', 'type': 'bcrypt'}
    ]

    for hashitem in hashdict:
        if re.match(hashitem['pattern'], hashstring):
            return hashitem['type']

    return False


if __name__ == "__main__":
    print(is_hash('a' * 40))
