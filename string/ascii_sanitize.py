#!/usr/bin/env python
# -*- coding: utf-8 -*-


def ascii_sanitize(self, s):
    """get printable string"""
    import string

    return filter(lambda x: x in string.printable, s)
