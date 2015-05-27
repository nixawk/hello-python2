#!/usr/bin/env python
# -*- coding: utf8 -*-

"""
lab:mechanize/ $  python mechanize-browser.links.py
https://www.blackhat.com
https://www.blackhat.com/us-15/
https://www.blackhat.com/upcoming.html
https://www.blackhat.com/upcoming.html
#
https://www.blackhat.com/exec-15/
https://www.blackhat.com/ldn-15/
https://www.blackhat.com/html/archives.html
https://www.blackhat.com/html/sponsors.html
https://www.blackhat.com/html/press.html
#
https://www.blackhat.com/about.html
https://www.blackhat.com/community.html
https://www.blackhat.com/review-board.html
https://www.blackhat.com/training-review-board.html
https://www.blackhat.com/html/contact.html
https://www.blackhat.com/code-of-conduct.html
http://legal.us.ubm.com/privacy-policy-highlights/
https://www.blackhat.com/mailing-list.html
........
"""

import mechanize

browser = mechanize.Browser()

# httperror_seek_wrapper: HTTP Error 403: Forbidden
browser.set_handle_robots(False)
# browser.set_handle_equiv(False)
browser.addheaders = [('User-Agent', 'Mozilla/5.0')]

# browser
browser.open('http://www.blackhat.com/')

# title
print browser.title()

for link in browser.links():
    print link.url
