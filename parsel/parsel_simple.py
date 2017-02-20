#!/usr/bin/python
# -*- coding: utf-8 -*-

# documentation: https://parsel.readthedocs.io/en/latest/
# $ pip install parsel

from parsel import Selector


html = u"""<html>
        <body>
            <h1>Hello, Parsel!</h1>
            <ul>
                <li><a href="http://example.com">Link 1</a></li>
                <li><a href="http://scrapy.org">Link 2</a></li>
            </ul
        </body>
        </html>"""

sel = Selector(html)

for node in sel.xpath('//li/a/text()'):
    print node.extract()

for node in sel.xpath('//li/a/@href'):
    print node.extract()
