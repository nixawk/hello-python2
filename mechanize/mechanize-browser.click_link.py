#!/usr/bin/env python
# -*- coding: utf8 -*-

import mechanize

# create a new Browser object
browser = mechanize.Browser()
browser.set_handle_robots(False)
browser.set_handle_equiv(False)
browser.addheaders = [('User-Agent', 'Mozilla/5.0')]

# open a link
browser.open('https://github.com/')
browser.select_form(nr=0)
browser.form['q'] = 'django'
browser.submit()

for link in browser.links():
    print link.url

# click html page
new_link = browser.click_link(text='API')
browser.open(new_link)

for link in browser.links():
    print link.url
