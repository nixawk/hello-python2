#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
   Name:         Baidu subdomains spider
   Author:       Nixawk
   Description:  spider demo site subdomains from baidu,
   Dork:         site:demo.com
                 site:demo.com -site:www.demo.com
"""

import requests
import urllib
import logging
import time
import random
import re


logging.basicConfig(level=logging.INFO, format="[+] %(message)s")
logger = logging.getLogger("BaiduSpider")


class Baidu(object):
    def __init__(self):
        """Baidu Hostname Enumerator
        """
        self.bdurl = 'http://www.baidu.com/s'

    def getSubdomains(self, domain, html):
        """extract subdomains from html response
        """
        regex = '<span class="g">\s*(?:\w*://)*(\S*?)\.%s[^<]*</span>' % domain
        return list(set(re.findall(regex, html)))

    def genSearchUrl(self, pn, wd):
        """generate baidu search url
        """
        return '%s?pn=%d&wd=%s' % (self.bdurl, pn, urllib.quote_plus(wd))

    def urlFilter(self, url):
        """baidu errors out at > 2054 characters notincluding the protocol
        """
        if len(url) > 2061:
            url = url[:2061]

        return url

    def request(self, url):
        """send http request
        """
        sess = requests.Session()
        return sess.get(url, allow_redirects=False)

    def spider(self, domain):
        """spider a single domain for subdomains
        """
        subdomains = []
        new = True
        page = 0
        nr = 10

        # site: demo.com
        query = 'site:%s' % domain

        while new:
            html = None

            # exclude [ -site:www.demo.com -site:app.demo.com ]
            exclude = ['-site:%s' % _ for _ in subdomains]

            # [ site:demo.com -site:www.demo.com -site:app.demo.com ]
            query2 = "%s %s" % (query, " ".join(exclude))
            logger.info(query2)

            # create baidu search url
            query_url = self.genSearchUrl((page * nr), query2)
            query_url = self.urlFilter(query_url)
            logger.debug(query_url)

            # send query to search engine
            resp = self.request(query_url)

            if resp.status_code != 200:
                logger.info(('Baidu has encountered an error.'))
                break

            # extract sites domains with regex
            html = resp.text
            sites = self.getSubdomains(domain, html)

            new = False

            # add subdomain to list if not already exists
            for site in sites:
                subdomain = "%s.%s".lower() % (site, domain)

                if subdomain not in subdomains:
                    subdomains.append(subdomain)

                    new = True
                    logger.info(subdomain)

            if not new:
                # exit if all subdomains have been found
                if u'>\u4e0b\u4e00\u9875&gt;<' not in html:
                    break
                else:
                    page += 1
                    new = True

                    logger.info('jumping to result: %d' % (page * nr + 1))

            logger.info('sleeping to avoid lockout...\n')
            time.sleep(random.randint(5, 15))

        return subdomains


if __name__ == "__main__":
    bd = Baidu()
    print("\n".join(bd.spider("wooyun.org")))
