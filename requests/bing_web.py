#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
   Name:         Bing subdomains spider
   Author:       Nixawk
   Description:  spider demo site subdomains from bing,
   Dork:         domain:demo.com
                 domain:demo.com -domain:www.demo.com
"""

import requests
import urllib
import logging
import time
import random
import re


logging.basicConfig(level=logging.INFO, format="[+] %(message)s")
logger = logging.getLogger("BingSpider")


class Bing(object):
    def __init__(self):
        """Bing Hostname Enumerator
        """
        self.bingurl = 'http://www.bing.com/search'

    def getSubdomains(self, domain, html):
        """extract subdomains from html response
        """
        regex = '"b_algo"><h2><a href="(?:\w*://)*(\S+?)\.%s[^"]*"' % domain
        return list(set(re.findall(regex, html)))

    def genSearchUrl(self, pn, wd):
        """generate search url
        """
        return '%s?first=%d&q=%s' % (self.bingurl, pn, urllib.quote_plus(wd))

    def urlFilter(self, url):
        """bing errors out at > 2054 characters notincluding the protocol
        """
        if len(url) > 2061:
            url = url[:2061]

        return url

    def request(self, url):
        """send http request
        """
        sess = requests.Session()
        sess.cookies['SRCHHPGUSR'] = 'NEWWND=0&NRSLT=50&SRCHLANG=&AS=1'

        return sess.get(url, allow_redirects=True)

    def spider(self, domain):
        """spider a single domain for subdomains
        """
        subdomains = []
        new = True
        page = 0
        nr = 50

        # site: demo.com
        query = 'domain:%s' % domain

        while new:
            html = None

            # exclude [ -domain:www.demo.com -domain:app.demo.com ]
            exclude = ['-domain:%s' % _ for _ in subdomains]

            # [ domain:demo.com -domain:www.demo.com -domain:app.demo.com ]
            query2 = "%s %s" % (query, " ".join(exclude))
            logger.info(query2)

            # create bing search url
            query_url = self.genSearchUrl((page * nr), query2)
            query_url = self.urlFilter(query_url)
            logger.debug(query_url)

            # send query to search engine
            resp = self.request(query_url)

            if resp.status_code != 200:
                logger.info(('Bing has encountered an error.'))
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
                if u'>Next</a>' not in html:
                    break
                else:
                    page += 1
                    new = True

                    logger.info('jumping to result: %d' % (page * nr + 1))

            logger.info('sleeping to avoid lockout...\n')
            time.sleep(random.randint(5, 15))

        return subdomains


if __name__ == "__main__":
    bing = Bing()
    print("\n".join(bing.spider("wooyun.org")))
