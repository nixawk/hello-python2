#!/usr/bin/Python
# -*- coding: utf-8 -*-

# http://www.w3schools.com/xsl/xpath_syntax.asp
# http://lxml.de/tutorial.html

from lxml import etree
import requests


def parse(html_response):
    tree = etree.HTML(html_response)
    for href in tree.xpath('//a/@href'):
        print(href)

    for a in tree.xpath('//a/text()'):
        print(a)


if __name__ == "__main__":
    parse(requests.get('https://www.yahoo.com/').content)
