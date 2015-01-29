#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Demostration:

[demo@core unicode]$ python unicode.py
Please a string to be unicoded: - englisch
- englisch
[demo@core unicode]$ python unicode.py
Please a string to be unicoded: 英语
英语
[demo@core unicode]$ python unicode.py
Please a string to be unicoded: 영어
영어
[demo@core unicode]$ python unicode.py
Please a string to be unicoded: اللغة الإنجليزية
اللغة الإنجليزية
[demo@core unicode]$ python unicode.py
Please a string to be unicoded:  английский
английский
"""


def getUnicode(value, encoding=None):
    if isinstance(value, unicode):
        return value

    else:
        try:
            return unicode(value, encoding or "utf-8")
        except (UnicodeDecodeError, TypeError):
            return unicode(str(value), errors="ignore")


u = raw_input('Please a string to be unicoded: ')
print getUnicode(u)
