#!/usr/bin/python
# -*- coding: utf-8 -*-

from bing import bing
from baidu import baidu
from yahoo import yahoo
from google import google
from netcraft import netcraft
from zoomeye import zoomeye
from censys import censys
from github import github
import re
import requests


class baidu_domain_spider(baidu):
    def __init__(self):
        super(baidu_domain_spider, self).__init__()

    def baidu_domain_search(self, domain, page=2, random_sleep=True):
        """parse domains from baidu spider results"""
        dork = "site:{}".format(domain)
        regex = re.compile('[a-zA-Z0-9]+\.{}'.format(domain), re.I | re.M)
        results = self.baidu_dork_search(dork, page=page,
                                         random_sleep=random_sleep)
        data = results[dork]  # [['title', 'href', 'link'], ... ]
        bd_domains = []

        if not data:
            return {domain: {'baidu': bd_domains}}

        for title, href, link in data:
            domains = regex.findall(href)
            for _ in domains:
                if _ in bd_domains:
                    continue
                bd_domains.append(_)

        return {domain: {'baidu': bd_domains}}


class bing_domain_spider(bing):
    def __init__(self):
        super(bing_domain_spider, self).__init__()

    def bing_domain_search(self, domain, page=2, random_sleep=False):
        """parse domains from bing spider results"""
        dork = "site:{}".format(domain)
        regex = re.compile('[a-zA-Z0-9]+\.{}'.format(domain), re.I | re.M)
        results = self.bing_dork_search(dork, page=page,
                                        random_sleep=random_sleep)
        data = results[dork]  # [['title', 'href']]
        bi_domains = []

        if not data:
            return {domain: {'bing': bi_domains}}

        for title, href in data:
            domains = regex.findall(href)
            for _ in domains:
                if _ in bi_domains:
                    continue
                bi_domains.append(_)

        return {domain: {'bing': bi_domains}}


class yahoo_domain_spider(yahoo):
    def __init__(self):
        super(yahoo_domain_spider, self).__init__()

    def yahoo_domain_search(self, domain, page=2, random_sleep=True):
        """parse domains from yahoo spider results"""
        dork = "site:{}".format(domain)
        regex = re.compile('[a-zA-Z0-9]+\.{}'.format(domain), re.I | re.M)
        results = self.yahoo_dork_search(dork, page=page,
                                         random_sleep=random_sleep)
        data = results[dork]  # [['title', 'href'], ... ]
        yh_domains = []

        if not data:
            return {domain: {'yahoo': yh_domains}}

        for title, href in data:
            domains = regex.findall(href)
            for _ in domains:
                if _ in yh_domains:
                    continue
                yh_domains.append(_)

        return {domain: {'yahoo': yh_domains}}


class google_domain_spider(google):
    def __init__(self):
        super(google_domain_spider, self).__init__()

    def google_domain_search(self, domain, pages=2, random_sleep=True):
        """parse domains from google spider results"""
        dork = "site:{}".format(domain)
        regex = re.compile('[a-zA-Z0-9]+\.{}'.format(domain), re.I | re.M)
        results = self.google_dork_search(dork, page=pages, random_sleep=True)

        data = results[dork]
        gg_domains = []

        if not data:
            return {domain: {'google': gg_domains}}

        for title, href, link in data:
            domains = regex.findall(href)
            for _ in domains:
                if _ in gg_domains:
                    continue
                gg_domains.append(_)

        return {domain: {'google': gg_domains}}


class netcraft_domain_spider(netcraft):
    def __init__(self):
        super(netcraft_domain_spider, self).__init__()

    def netcraft_domain_search(self, domain, page=0, random_sleep=True):
        nt_domains = self.domain_search(domain, page=page,
                                        random_sleep=random_sleep)
        return {domain: {'netcraft': nt_domains}}


class zoomeye_domain_spider(zoomeye):
    def __init__(self, username, password):
        super(zoomeye_domain_spider, self).__init__(username, password)
        self.username = username
        self.password = password
        self.login()

    def zoomeye_domain_search(self, domain, page=0):
        dork = 'site:{}'.format(domain)
        data = self.zoomeye_dork_search(dork, page=page, resource='web')
        zm_domains = [_['site'] for _ in data]
        return {domain: {'zoomeye': zm_domains}}


class censys_domain_spider(censys):
    def __init__(self, uid, secret):
        super(censys_domain_spider, self).__init__()
        self.uid = uid
        self.secret = secret

    def censys_domain_search(self, domain, page=0):
        dork = domain
        dorktype = 'certificates'
        cs_domains = []
        regex = re.compile('[a-zA-Z0-9]+\.{}'.format(domain), re.I | re.M)
        for _page in range(page):
            data = self.censys_dork_search(
                self.uid, self.secret, domain, dorktype, page=page)
            status, results, metadata = self.parse_results(data)
            for result in results:
                item = result['parsed.subject_dn']
                item = ''.join(item)
                domains = regex.findall(item)
                for _ in domains:
                    if _ in cs_domains:
                        continue
                    cs_domains.append(_)
        return {domain: {'censys': cs_domains}}


class github_domain_spider(github):
    def __init__(self):
        super(github_domain_spider, self).__init__()

    def github_domain_search(self, domain):
        gt_domains = []  # github search domain is too slow.
        regex = re.compile('[a-zA-Z0-9]+\.{}'.format(domain), re.I | re.M)
        total_count, incomplete_results, items = self.search_repositories(
            domain)
        links = []
        for item in items:  # repo or user is a must.
            dork = '{} in:file repo:{}'.format(domain, item['full_name'])
            total_count, incomplete_results, items = self.search_code(domain)
            for item in items:
                link = item['html_url']
                if link not in links:
                    links.append(link)

        for link in links:
            resp = requests.get(link)
            domains = regex.findall(resp.text)
            for _ in domains:
                if _ in gt_domains:
                    continue
                gt_domains.append(_)
        return {domain: {'github': gt_domains}}


class domainspider(baidu_domain_spider,
                   bing_domain_spider,
                   yahoo_domain_spider):
    def __init__(self):
        super(domainspider, self).__init__()

    def search(self, domain, page=2, random_sleep=True):
        domains = []
        bdret = self.baidu_domain_search(domain, page=page,
                                         random_sleep=random_sleep)
        biret = self.bing_domain_search(domain, page=page,
                                        random_sleep=random_sleep)
        yhret = self.yahoo_domain_search(domain, page=page,
                                         random_sleep=random_sleep)

        domains.extend(bdret[domain]['baidu'])
        domains.extend(biret[domain]['bing'])
        domains.extend(yhret[domain]['yahoo'])

        return list(set(domains))


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 2:
        print("{} <domain> : search subdomains".format(sys.argv[0]))
        sys.exit(0)

    domain = sys.argv[1]
    print("[+] collecting {} subdomains....".format(domain))
    ds = domainspider()
    print(ds.search(domain, page=10, random_sleep=True))
