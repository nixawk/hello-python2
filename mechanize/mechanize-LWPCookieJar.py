#!/usr/bin/env python
# -*- coding: utf8 -*-

import mechanize

cj = mechanize.LWPCookieJar()
# cj.revert("cookies.log")
opener = mechanize.build_opener(mechanize.HTTPCookieProcessor(cj))
opener.open("http://github.com/")
cj.save("cookies.log")
