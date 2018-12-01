#!/usr/bin/python
# -*- coding: utf-8 -*-

import dns.resolver
import dns.rdatatype
import dns.query
import dns.zone
import dns.dnssec
import dns.reversename
import randoms


__class__ = ['idns']
__funcs__ = ['query_A', 'query_AAAA', 'query_CNAME', 'query_MX', 'query_NS',
             'query_SOA', 'query_SRV', 'query_TXT', 'query_AXFR', 'query_PTR']


class idns(object):
    """
    Collect dns information in both passive and offensive modes.
      passive mode:
        - dns query
        - OSInt

      offensibe mode:
        - spider websites default page
        - scan websites certificates
    """
    def __init__(self, ns_server=None, dns_timeout=8.0):
        """
        Init idns instance, and query multi dns records.
        param: ns_server
            specify a nameserver for dns query.
        param: dns_timeout
            dns response timeout
        """
        super(idns, self).__init__()

        if ns_server:
            self._idns = dns.resolver.Resolver(configure=False)
            self._idns.nameservers = [ns_server]
        else:
            self._idns = dns.resolver.Resolver(configure=True)

        self._idns.lifetime = dns_timeout
        self._idns.timeout = dns_timeout

    def dns_query(self, *args, **kwds):
        """set dns query options, and handle dns query error"""
        kwds.update({'raise_on_no_answer': False})
        kwds.update({'tcp': False})
        result = None
        try:
            result = self._idns.query(*args, **kwds)
        except Exception as err:
            print(str(err))
        return result

    def dns_wildcard(self, domain):
        """Check if dns wildcard is enable. A wildcard DNS record is a record
        in a DNS zone that will match requests for non-existent domain names.
        References:
            https://en.wikipedia.org/wiki/Wildcard_DNS_record
            https://tools.ietf.org/html/rfc1034
        """
        wild_domain = "*.{}".format(domain)
        wild_result = self.query_A(wild_domain)[wild_domain]['A']
        if wild_result:
            print("{} has probably a (*) wildcard".format(domain))
            return True

        rand_prefix = randoms.rand_text_alpha(32)
        rand_domain = "{}.{}".format(rand_prefix, domain)
        rand_result = self.query_A(rand_domain)[rand_domain]['A']
        if rand_result:
            print("{} has probably a (rand) wildcard".format(domain))
            return True

        print("{} does not really have wildcards".format(domain))
        return False

    def query_A(self, domain):
        """query DNS A records.
        ex: {'www.google.com': {'A': [u'93.46.8.89']}}
        """
        resp = self.dns_query(domain, rdtype=dns.rdatatype.A)
        # collect dns query records
        data = [_.address
                for _answer in resp.response.answer
                for _ in _answer
                if _.rdtype == dns.rdatatype.A] if resp else []
        return {domain: {'A': data}}

    def query_AAAA(self, domain):
        """query DNS AAAA records.
        ex: {'www.google.com': {'AAAA': []}}
        """
        resp = self.dns_query(domain, rdtype=dns.rdatatype.AAAA)
        data = [_.address
                for _answer in resp.response.answer
                for _ in _answer
                if _.rdtype == dns.rdatatype.AAAA] if resp else []
        return {domain: {'AAAA': data}}

    def query_CNAME(self, domain):
        """query DNS CNAME records.
        ex: {'www.yahoo.com': {'CNAME': ['fd-fp3.wg1.b.yahoo.com.']}}
        """
        resp = self.dns_query(domain, rdtype=dns.rdatatype.CNAME)
        data = [_.target.to_text()
                for _answer in resp.response.answer
                for _ in _answer
                if _.rdtype == dns.rdatatype.CNAME] if resp else []
        return {domain: {'CNAME': data}}

    def query_MX(self, domain):
        """query DNS MX records.
        ex: {'google.com': {'MX': ['aspmx.l.google.com.',
                                   'alt3.aspmx.l.google.com.',
                                   'alt4.aspmx.l.google.com.',
                                   'alt1.aspmx.l.google.com.',
                                   'alt2.aspmx.l.google.com.']}}
        """
        resp = self.dns_query(domain, rdtype=dns.rdatatype.MX)
        data = [_answer.exchange.to_text()
                for _answer in resp
                if _answer.rdtype == dns.rdatatype.MX] if resp else []
        return {domain: {'MX': data}}

    def query_NS(self, domain):
        """query DNS NS records.
        ex: {'google.com': {'NS': ['ns3.google.com.','ns1.google.com.',
                                   'ns4.google.com.', 'ns2.google.com.']}}
        """
        resp = self.dns_query(domain, rdtype=dns.rdatatype.NS)
        data = [_answer.target.to_text()
                for _answer in resp
                if _answer.rdtype == dns.rdatatype.NS] if resp else []
        return {domain: {'NS': data}}

    def query_SOA(self, domain):
        """query DNS SOA records.
        ex: {'google.com': {'SOA': ['ns4.google.com.']}}
        """
        resp = self.dns_query(domain, rdtype=dns.rdatatype.SOA)
        data = [_answer.mname.to_text()
                for _answer in resp
                if _answer.rdtype == dns.rdatatype.SOA] if resp else []
        return {domain: {'SOA': data}}

    def query_SRV(self, domain):
        """query DNS SRV records.
        """
        resp = self.dns_query(domain, rdtype=dns.rdatatype.SRV)
        data = [_answer.target.to_text()
                for _answer in resp
                if _answer.rdtype == dns.rdatatype.SRV] if resp else []
        return {domain: {'SRV': data}}

    def query_TXT(self, domain):
        """query DNS TXT records, normally, it includes [SPF] information.
        ex: {'yahoo.com': {'TXT': ['v=spf1 redirect=_spf.mail.yahoo.com']}}
        """
        resp = self.dns_query(domain, rdtype=dns.rdatatype.TXT)
        data = [_
                for _answer in resp
                for _ in _answer.strings
                if resp.rdtype == dns.rdatatype.TXT] if resp else []
        return {domain: {'TXT': data}}

    def query_AXFR(self, domain):
        """query DNS AXFR records,
        """
        nameservers = self.query_NS(domain)[domain]['NS']
        data = []
        for nameserver in nameservers:
            # dns.zone.from_xfr raise an exception: No answer or RRset not for qname
            resp = dns.zone.from_xfr(dns.query.xfr(nameserver, domain))
            # If exception occurs, program exits here.

            if resp:
                data = [resp.to_text()]
                break
        return {domain: {'AXFR': data}}

    def query_PTR(self, ip):
        """query DNS PTR records, ex:
        {'8.8.8.8': {'PTR': ['google-public-dns-a.google.com.']}}
        """
        rvl = dns.reversename.from_address(ip)
        resp = self.dns_query(rvl, rdtype=dns.rdatatype.PTR)
        data = [_answer.target.to_text()
                for _answer in resp
                if _answer.rdtype == dns.rdatatype.PTR] if resp else []
        return {ip: {'PTR': data}}


def demo_idns():
    """Just a demo test for class idns"""
    from pprint import pprint

    data = {}
    xdns = idns()
    domain = 'zonetransfer.me'

    xdns.dns_wildcard(domain)  # dns wildcard checks

    data[domain] = {}
    data[domain].update(xdns.query_A(domain)[domain])
    data[domain].update(xdns.query_A(domain)[domain])
    data[domain].update(xdns.query_CNAME(domain)[domain])
    data[domain].update(xdns.query_MX(domain)[domain])
    data[domain].update(xdns.query_NS(domain)[domain])
    data[domain].update(xdns.query_SOA(domain)[domain])
    data[domain].update(xdns.query_AXFR(domain)[domain])
    data[domain].update(xdns.query_TXT(domain)[domain])  # contains [SPF] info

    pprint(data)


if __name__ == '__main__':
    demo_idns()

# Thanks:
#    https://digi.ninja/projects/zonetransferme.php
#    https://en.wikipedia.org/wiki/List_of_DNS_record_types
