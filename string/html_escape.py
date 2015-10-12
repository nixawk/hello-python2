#!/usr/bin/env python
# -*- coding: utf-8 -*-


def html_escape(s):
    escapes = {
        '&': '&amp;',
        '"': '&quot;',
        "'": '&apos;',
        '>': '&gt;',
        '<': '&lt;'
    }

    # return ''.join(map(lambda x: escapes.get(x, x), s))
    return ''.join(escapes.get(c, c) for c in s)

html = "<script>alert(/080/)</script>"
print(html_escape(html))
