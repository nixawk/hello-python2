#!/usr/bin/python
# -*- coding: utf-8 -*-

from idns import idns
from worker import GeventWorker


class idns_bruteforce(idns, GeventWorker):
    """subdomain, tld, gtld, reverse bruteforce"""
    def __init__(self, domain='google.com', subdomains_wd='tlddomains.txt'):
        super(idns_bruteforce, self).__init__()
        self.domain = domain
        self.tld_wd = open(subdomains_wd)
        self.dns_wildcard(self.domain)  # check dns wildcard

    def fake_job(self):
        """Custom job"""
        suffix = self.tld_wd.readline().strip()
        if suffix == '':
            self._exitpool = True

        subdomain = "{}.{}".format(self.domain, suffix)
        data = self.query_A(subdomain)[subdomain]['A']
        print({subdomain: {'A': data}})
        return {subdomain: {'A': data}}


def demo_idns_bruteforce():
    """Just a demo test for class idns_bruteforce"""
    bt = idns_bruteforce()
    bt.work()

if __name__ == '__main__':
    demo_idns_bruteforce()
