#!/usr/bin/python
# -*- coding: utf-8 -*-

from idns import idns
from worker import GeventWorker


class idns_bruteforce(idns, GeventWorker):
    """subdomain, tld, gtld, reverse bruteforce"""
    def __init__(self, domain='google.com', subdomains_wd='subdomains.txt'):
        super(idns_bruteforce, self).__init__()
        self.domain = domain
        self.domains = []
        self.subdomains_wd = open(subdomains_wd)
        # self.dns_wildcard(self.domain)  # check dns wildcard

    def fake_job(self):
        """Custom job"""
        prefix = self.subdomains_wd.readline().strip()
        if prefix == '':
            self._exitpool = True

        subdomain = "{}.{}".format(prefix, self.domain)
        data = self.query_A(subdomain)[subdomain]['A']
        print({subdomain: {'A': data}})
        if data:
            self.domains.append({subdomain: {'A': data}})
        return {subdomain: {'A': data}}


def demo_idns_bruteforce():
    """Just a demo test for class idns_bruteforce"""
    bt = idns_bruteforce()
    bt.work()

if __name__ == '__main__':
    demo_idns_bruteforce()
