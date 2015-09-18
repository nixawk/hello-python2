#!/usr/bin/env python
# -*- encoding: utf-8 -*-

# ################################## #
#   Information Gathering Toolkit    #
# ---------------------------------- #
#   Author: nixawk                   #
#                                    #
# ################################## #

__author__ = "nixawk"
__version__ = "1.2.0"
__license__ = "GNU license"
__description__ = "get dns details"

__classes__ = ["dnsinfo"]

__funcs__ = [
    "get_a",
    "get_cname",
    "get_aaaa",
    "get_mx",
    "get_ns",
    "get_soa",
    "get_spf",
    "get_txt",
    "get_ptr",
    "get_srv",
    "get_nsec",
    "get_xfr",
    "zone_transfer",
    "get_bindver",
    "dns_wildcard",
    "google_search",
    "brute_reverse_c",
    "brute_domain",
    "brute_srv",
    "brute_gtld",
    "brute_tld",
    "info"
    "_threads",
    "_handle_exception"
]

# standard library modules
# http://www.dnspython.org/
# http://chrisarndt.de/projects/threadpool/

import dns.resolver
import dns.rdatatype
import dns.query
import dns.zone
import dns.dnssec
import random
import socket
import netaddr
# import re

import threadpool

# from optparse import OptionParser
import logging

logging.basicConfig(level=logging.DEBUG,
                    format='%(message)-20s')


# /* multi threads to do tasks */
def _threads(threadnum, func, args_kwds, callback=None):
    '''
    def callback(request, data):
        if len(data[0]['Address']) > 0:
            logging.info(data)
        pass
        # print "callback: %s: %s" % (request.requestID, data)
    '''

    def exp_callback(request, exc_info):
        pass

    requests = threadpool.makeRequests(func,
                                       args_kwds,
                                       callback,
                                       exp_callback)

    pool = threadpool.ThreadPool(threadnum)

    [pool.putRequest(req) for req in requests]

    while True:
        try:
            pool.poll()
        except KeyboardInterrupt:
            break
        except threadpool.NoResultsPending:
            break

    if pool.dismissedWorkers:
        pool.joinAllDismissedWorkers()


# /* DNS QUERY TOOLKIT */
class dnsinfo(object):
    def __init__(self, ns_server=None, dns_timeout=8.0):

        if ns_server:
            self._res = dns.resolver.Resolver(configure=False)
            self._res.nameservers = ns_server
        else:
            # no nameserver set
            self._res = dns.resolver.Resolver(configure=True)

        self._res.lifetime = dns_timeout
        self._res.timeout = dns_timeout

    def _handle_exception(self, func, *args, **kwds):
        try:
            record = func(*args, **kwds)

        # /* dns.exception */
        except dns.exception.Timeout:
            record = None
        except dns.exception.FormError:
            record = None
        except dns.exception.SyntaxError:
            record = None

        # /* dns.resolver */
        except dns.resolver.NXDOMAIN:
            record = None
        except dns.resolver.NoNameservers:
            record = None
        except dns.resolver.NoAnswer:
            record = None

        # /* dns.name */
        except dns.name.EmptyLabel:
            record = None

        return record

    # /* Get DNS A records */
    def get_a(self, domain):
        # record.canonical_name
        # record.expiration
        # record.qname
        # record.response
        # record.rrset

        logging.debug("[?] trying to get a record: \t %s" % domain)

        record = self._handle_exception(self._res.query, domain, 'A')

        # records exists
        if record:
            return [{'Target': domain, 'Type': 'A', 'Address': _.address}
                    for _anwser in record.response.answer
                    for _ in _anwser
                    if _.rdtype == dns.rdatatype.A]
        else:
            return [{'Target': domain, 'Type': 'A',
                     'Address': ''}]

    # /* Get CNAME records */
    def get_cname(self, domain):
        logging.debug("[?] trying to get cname record: \t %s" % domain)

        record = self._handle_exception(self._res.query, domain, 'CNAME')

        # records exists
        if record:
            return [{'Target': domain, 'Type': 'CNAME',
                     'Address': _.target.to_text()[:-1]}
                    for _anwser in record.response.answer
                    for _ in _anwser
                    if _.rdtype == dns.rdatatype.CNAME]
        else:
            return [{'Target': domain, 'Type': 'CNAME',
                     'Address': ''}]

    # /* Get AAAA records */
    def get_aaaa(self, domain):
        logging.debug("[?] trying to get aaaa record: \t %s" % domain)

        record = self._handle_exception(self._res.query, domain, 'AAAA')

        # records exists
        if record:
            return [{'Target': domain, 'Type': 'AAAA',
                     'Address': _.address}
                    for _anwser in record.response.answer
                    for _ in _anwser
                    if _.rdtype == dns.rdatatype.AAAA]
        else:
            return [{'Target': domain, 'Type': 'AAAA',
                     'Address': ''}]

    # /* Get MX records */
    def get_mx(self, domain):
        logging.debug("[?] trying to get mx record: \t %s" % domain)
        record = self._handle_exception(self._res.query, domain, 'MX')

        # records exists
        if record:
            return [{'Target': domain, 'Type': 'MX',
                     'Address': _anwser.exchange.to_text()[:-1]}
                    for _anwser in record]
        else:
            return [{'Target': domain, 'Type': 'MX',
                     'Address': ''}]

    # /* Get NS records */
    def get_ns(self, domain):
        logging.debug("[?] trying to get ns record: \t %s" % domain)
        record = self._handle_exception(self._res.query, domain, 'NS')

        if record:
            return [{'Target': domain, 'Type': 'NS',
                     'Address': _anwser.target.to_text()[:-1]}
                    for _anwser in record]
        else:
            return [{'Target': domain, 'Type': 'NS',
                     'Address': ''}]

    # /* Get SOA records */
    def get_soa(self, domain):
        logging.debug("[?] trying to get soa record: \t %s" % domain)
        record = self._handle_exception(self._res.query, domain, 'SOA')

        if record:
            return [{'Target': domain, 'Type': 'SOA',
                     'Address': _anwser.mname.to_text()[:-1]}
                    for _anwser in record]
        else:
            return [{'Target': domain, 'Type': 'SOA',
                     'Address': ''}]

    # /* Get SPF records */
    def get_spf(self, domain):
        logging.debug("[?] trying to get spf record: \t %s" % domain)
        record = self._handle_exception(self._res.query, domain, 'SPF')

        if record:
            return [{'Target': domain, 'Type': 'SPF',
                     'Address': _anwser.strings}
                    for _anwser in record]
        else:
            return [{'Target': domain, 'Type': 'SPF',
                     'Address': ''}]

    # /* Get TXT records */
    def get_txt(self, domain):
        logging.debug("[?] trying to get txt record: \t %s" % domain)
        record = self._handle_exception(self._res.query, domain, 'TXT')

        if record:
            return [{'Target': domain, 'Type': 'TXT',
                     'Address': _anwser.strings[0]}
                    for _anwser in record]
        else:
            return [{'Target': domain, 'Type': 'TXT',
                     'Address': ''}]

    # /* Get PTR records */
    def get_ptr(self, ip):
        logging.debug("[?] trying to get ptr record: \t %s" % ip)
        rvl_rd = self._handle_exception(dns.reversename.from_address, ip)
        record = self._handle_exception(self._res.query, rvl_rd, 'PTR')

        if record:
            return [{'Target': ip, 'Type': 'PTR',
                     'Address': _anwser.target.to_text()[:-1]}
                    for _anwser in record]
        else:
            return [{'Target': ip, 'Type': 'PTR',
                     'Address': ''}]

    # /* Get SRV records */
    def get_srv(self, domain):
        logging.debug("[?] trying to get srv record: \t %s" % domain)
        record = self._handle_exception(self._res.query, domain, 'SRV')

        if record:
            return [{'Target': domain, 'Type': 'SRV',
                     'Address': _anwser.target.to_text()[:-1]}
                    for _anwser in record]
        else:
            return [{'Target': domain, 'Type': 'SRV',
                     'Address': ''}]

    # /* Get NSEC records */
    def get_nsec(self, domain):
        logging.debug("[?] trying to get nsec record: \t %s" % domain)
        record = self._handle_exception(self._res.query, domain, 'NSEC')

        if record:
            return [{'Target': domain, 'Type': 'NSEC',
                     'Address': record}]
        else:
            return [{'Target': domain, 'Type': 'NSEC',
                     'Address': ''}]

    # /* Get xfr records */
    def get_xfr(self, nameserver, domain):
        logging.debug("[?] trying to get xfr record: \t %s" % domain)
        record = self._handle_exception(
            dns.query.xfr, nameserver, domain)

        if record:
            return [{'Target': domain, 'Type': 'XFR',
                     'Address': _anwser.to_text()}
                    for _anwser in record]
        else:
            return [{'Target': domain, 'Type': 'XFR',
                     'Address': ''}]

    # /* Get DNS Zone Transfer records */
    def zone_transfer(self, domain):
        # cost more time during dns query
        ''' zone transfer records
        {
        'Target': host or domain,
        'Type': A, AAAA, .....
        'Address': record text
        },
        { ... },
        { ... }
        '''
        zone_rds = []

        NS_records = self.get_ns(domain)

        for ns_record in NS_records:
            # { 'Target': domain,
            #   'Type': 'XFR',
            #   'Address': nameserver}
            ns = ns_record['Address']
            try:
                # _handle_exception failed to return a generator
                logging.info("[?] trying to zone transfer - %s" % ns)
                z = dns.zone.from_xfr(
                    dns.query.xfr(ns, domain))

            except dns.exception.FormError:
                pass
            except socket.error:
                pass
            else:
                print "[+] dns transfer: %s" % ns

                for (name, rdataset) in z.iterate_rdatasets():
                    for rdata in rdataset:

                        # /* A */
                        if rdata.rdtype == dns.rdatatype.A:
                            addr = {'Address': rdata.address}
                            zone_rds.append({'Target': ns,
                                             'Type': 'A',
                                             'Address': addr})

                            print 'A: \t', addr

                        # /* AAAA */
                        if rdata.rdtype == dns.rdatatype.AAAA:
                            addr = {'Address': rdata.address}
                            zone_rds.append({'Target': ns,
                                             'Type': 'AAAA',
                                             'Address': addr})

                            print "AAAA: \t", rdata.address

                        # /* CNAME */
                        if rdata.rdtype == dns.rdatatype.CNAME:
                            addr = {'Address': "%s.%s" % (
                                rdata.target.to_text(),
                                domain)}

                            zone_rds.append({'Target': ns,
                                             'Type': 'CNAME',
                                             'Address': addr})

                            print "CNAME: \t", addr

                        # /* HINFO */
                        if rdata.rdtype == dns.rdatatype.HINFO:
                            addr = {'Cpu': rdata.cpu,
                                    'Os': rdata.os}
                            zone_rds.append({'Target': ns,
                                             'Type': 'HINFO',
                                             'Address': addr})

                            print 'HINFO: \t', addr

                        # /* MX */
                        if rdata.rdtype == dns.rdatatype.MX:
                            addr = {'Address': rdata.exchange.to_text()}

                            zone_rds.append({'Target': ns,
                                             'Type': 'MX',
                                             'Address': addr})

                            print "MX: \t", addr

                        # /* NS */
                        if rdata.rdtype == dns.rdatatype.NS:
                            addr = {'Address': "%s.%s" % (
                                rdata.target.to_text(),
                                domain)}
                            zone_rds.append({'Target': ns,
                                             'Type': 'NS',
                                             'Address': addr})
                            print 'NS: \t', addr

                        # /* PTR */
                        if rdata.rdtype == dns.rdatatype.PTR:
                            addr = {'Address': rdata.target.to_text()}
                            zone_rds.append({'Target': ns,
                                             'Type': 'PTR',
                                             'Address': addr})

                            print "PTR: \t", addr

                        # /* SOA */
                        if rdata.rdtype == dns.rdatatype.SOA:
                            addr = {'Address': "%s.%s" % (
                                rdata.mname.to_text(),
                                domain
                            )}
                            zone_rds.append({'Target': ns,
                                             'Type': 'SOA',
                                             'Address': addr})
                            print 'SOA: \t', addr

                        # /* SPF */
                        if rdata.rdtype == dns.rdatatype.SPF:
                            addr = {'Address': rdata.strings}
                            zone_rds.append({'Target': ns,
                                             'Type': 'SPF',
                                             'Address': addr})

                            print 'SPF: \t', addr

                        # /* SRV */
                        if rdata.rdtype == dns.rdatatype.SRV:
                            addr = {'Address': rdata.target.to_text()}
                            zone_rds.append({'Target': ns,
                                             'Type': 'SRV',
                                             'Address': addr})

                            print 'SRV: \t', addr

                        # /* TXT */
                        if rdata.rdtype == dns.rdatatype.TXT:
                            addr = {'Address': rdata.strings[0]}
                            zone_rds.append({'Target': ns,
                                             'Type': 'TXT',
                                             'Address': addr})

                            print 'TXT: \t', addr

                        # /* WKS */
                        if rdata.rdtype == dns.rdatatype.WKS:
                            addr = {'Address': rdata.address,
                                    'Bitmap': rdata.bitmap,
                                    'Protocol': rdata.protocol}
                            zone_rds.append({'Targer': ns,
                                             'Type': 'WKS',
                                             'Address': addr})

                            print 'WKS: \t', addr

                        # /* RP */
                        if rdata.rdtype == dns.rdatatype.RP:
                            addr = {'Address': rdata.txt.to_text,
                                    'Mbox': rdata.mbox.to_text()}
                            zone_rds.append({'Targer': ns,
                                             'Type': 'RP',
                                             'Address': addr})
                            print 'RP: \t', addr

                        # /* AFSDB */
                        if rdata.rdtype == dns.rdatatype.AFSDB:
                            addr = {'Hostname': rdata.hostname.to_text(),
                                    'Subtype': rdata.subtype}
                            zone_rds.append({'Targer': ns,
                                             'Type': 'AFSDB',
                                             'Address': addr})
                            print 'AFSDB: \t', addr

                        # /* LOC */
                        if rdata.rdtype == dns.rdatatype.LOC:
                            addr = {'Address': rdata.to_text()}
                            zone_rds.append({'Target': ns,
                                             'Type': 'LOC',
                                             'Address': addr})

                            print 'LOC: \t', addr

                        # /* X25 */
                        if rdata.rdtype == dns.rdatatype.X25:
                            addr = {'Address': rdata.address}
                            zone_rds.append({'Target': ns,
                                             'Type': 'X25',
                                             'Address': addr})

                            print 'X25: \t', addr

                        # /* ISDN */
                        if rdata.rdtype == dns.rdatatype.ISDN:
                            addr = {'Address': rdata.address}
                            zone_rds.append({'Target': ns,
                                             'Type': 'ISDN',
                                             'Address': addr})

                            print 'ISDN: \t', addr

                        # /* RT */
                        if rdata.rdtype == dns.rdatatype.RT:
                            addr = {'Address': rdata.address}
                            zone_rds.append({'Target': ns,
                                             'Type': 'RT',
                                             'Address': addr})

                            print 'RT: \t', addr

                        # /* NSAP */
                        if rdata.rdtype == dns.rdatatype.NSAP:
                            addr = {'Address': rdata.address}
                            zone_rds.append({'Target': ns,
                                             'Type': 'NSAP',
                                             'Address': addr})

                            print 'NSAP: \t', addr

                        # /* NAPTR */
                        if rdata.rdtype == dns.rdatatype.NAPTR:
                            addr = {'Order': rdata.order,
                                    'Perference': rdata.perference,
                                    'Regexp': rdata.regexp,
                                    'Replacement': rdata.replacement.to_text(),
                                    'Service': rdata.service}
                            zone_rds.append({'Target': ns,
                                             'Type': 'NAPTR',
                                             'Address': addr})

                            print 'NAPTR: \t', addr

                        # /* CERT */
                        if rdata.rdtype == dns.rdatatype.CERT:
                            addr = {'Algorithm': dns.dnssec.algorithm_to_text(
                                rdata.algorithm
                            ),
                                'Certificate': rdata.certificate,
                                'Certiticate_type': rdata.certificate_type,
                                'Key_tag': rdata.key_tag}
                            zone_rds.append({'Target': ns,
                                             'Type': 'CERT',
                                             'Address': addr})
                            print 'CERT: \t', addr

                        # /* SIG */
                        if rdata.rdtype == dns.rdatatype.SIG:
                            addr = {'Algorithm': dns.dnssec.algorithm_to_text(
                                rdata.algorithm
                            ),
                                'Expiration': rdata.expiration,
                                'Inception': rdata.inception,
                                'Key_tag': rdata.key_tag,
                                'Lables': rdata.labels,
                                'Original_ttl': rdata.original_ttl,
                                'Signature': rdata.signature,
                                'Singer': rdata.singer,
                                'Type_covered': rdata.type_covered}

                            zone_rds.append({'Target': ns,
                                             'Type': 'SIG',
                                             'Address': addr})
                            print 'SIG: \t', addr

                        # /* RRSIG */
                        if rdata.rdtype == dns.rdatatype.RRSIG:
                            addr = {'Algorithm': dns.dnssec.algorithm_to_text(
                                rdata.algorithm
                            ),
                                'Expiration': rdata.expiration,
                                'Inception': rdata.inception,
                                'Key_tag': rdata.key_tag,
                                'Lables': rdata.labels,
                                'Original_ttl': rdata.original_ttl,
                                'Signature': rdata.signature,
                                'Singer': rdata.singer,
                                'Type_covered': rdata.type_covered}

                            zone_rds.append({'Target': ns,
                                             'Type': 'RRSIG',
                                             'Address': addr})
                            print 'RRSIG: \t', addr

                        # /* DNSKEY */
                        if rdata.rdtype == dns.rdatatype.DNSKEY:
                            addr = {'Algorithm': dns.dnssec.algorithm_to_text(
                                rdata.algorithm
                            ),
                                'Flags': rdata.flags,
                                'Key': dns.rdata._hexify(rdata.key),
                                'Protocol': rdata.protocol}
                            zone_rds.append({'Target': ns,
                                             'Type': 'DNSKEY',
                                             'Address': addr})
                            print 'DNSKEY: \t', addr

                        # /* DS */
                        if rdata.rdtype == dns.rdatatype.DS:
                            addr = {'Algorithm': dns.dnssec.algorithm_to_text(
                                rdata.algorithm
                            ),
                                'Gateway': rdata.gateway,
                                'Gateway_type': rdata.gateway_type,
                                'Key': dns.rdata._hexify(rdata.key),
                                'Precedence': rdata.precedence}

                            zone_rds.append({'Target': ns,
                                             'Type': 'DS',
                                             'Address': addr})
                            print 'DS: \t', addr

        # return zone transfer records
        return zone_rds

    # /* get bing name server version */
    def get_bindver(self, nameserver):
        pass

    # /* check if wildcards are enabled on the target domain */
    def dns_wildcard(self, domain):
        '''make twice dns A record request to
        check that if dns wildcard is enable or not
        '''
        _ = '0123456789abcdef'
        'ghijklmnopqrstuvwxyz'
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

        for i in range(2):
            prefix = ''.join(random.Random().sample(
                _,
                random.randint(0, len(_))
            ))
            domain = '%s.%s' % (prefix, domain)
            ip = self.get_a(domain)[0]['Address']
            logging.debug('[*] check dns wildcard: \t%s' % domain)

            if 0 < len(ip):
                logging.info('[+] dns wildcard enable')
                return ip

        return ''

    def cidr_24(self, ip):
        _ip = netaddr.IPAddress(ip)
        return "%s.1/24" % (".".join(map(str, _ip.words[:-1])))

    # /* brute reverse - c ip range */
    def brute_reverse_c(self, domain):
        _cidrs = []
        _domains = []

        def callback(request, data):
            if 0 < len(data[0]['Address']):
                _domains.append(data)

        # /* get cidrs records */
        for record in self.get_a(domain):
            ip = record['Address']

            # /* if a ip address returns */
            if 0 < len(ip):
                _cidr = self.cidr_24(ip)

                if _cidr not in _cidrs:
                    _cidrs.append(_cidr)

                # /* get ip reverse domains */
                    ips = [str(ip)
                           for ip in netaddr.IPNetwork(_cidr)]

                    _threads(16, self.get_ptr, ips,
                             callback=callback)

        # print netaddr.cidr_merge(ips)
        return (_cidrs, _domains)

    # /* brute dns domain */
    def brute_domain(self, domain,
                     prefix,
                     verbose=False,
                     ignore_wildcard=True):
        brt_dom = []

        logging.debug("[?] trying to brute domain %s" % domain)

        # /* dns wildcard check*/
        if ignore_wildcard:
            pass
        else:
            ip = self.dns_wildcard(domain)
            if 0 < len(ip):
                logging.debug('[+] dns wildcard ip: \t', ip)

        brt_domain = "%s.%s" % (prefix, domain)
        brt_ip = self.get_a(brt_domain)[0]['Address']

        # /* show all brute records*/
        if verbose:
            logging.debug("[+] brute dns domain name: \t%s\t:%s" % (
                brt_domain, brt_ip))
        else:
            # /* only show valid record */
            if 0 < len(brt_ip):
                logging.info("[+] brute dns domain name: \t%s\t:%s" % (
                    brt_domain, brt_ip))

        brt_dom.append({'Target': brt_domain,
                        'Type': 'brt_dom',
                        'Address': brt_ip})

        return brt_dom

    def multi_brute_domain(self, domain, threadnum, wordlist):
        records = []

        # /* callback function */
        def callback(request, data):
            if 0 < len(data[0]['Address']):
                records.extend(data)

        with open(wordlist) as wdf:
            args_kwds = [
                ((domain, prefix.strip()), {})
                for prefix in wdf]

        # /* multi thread for brute domain */
        logging.debug('[+] %s threads' % threadnum)

        _threads(int(threadnum), self.brute_domain, args_kwds,
                 callback=callback)

        return records

    # /* brute dns srv record */
    def brute_srv(self, domain,
                  verbose=False):

        # /* save dns srv records */
        srv_ret = []

        # /* srv records */
        srv_rds = [
            '_gc._tcp.', '_kerberos._tcp.', '_kerberos._udp.',
            '_ldap._tcp.', '_test._tcp.',
            '_sips._tcp.', '_sip._udp.', '_sip._tcp.',
            '_aix._tcp.', '_aix._tcp.',
            '_finger._tcp.', '_ftp._tcp.',
            '_http._tcp.', '_nntp._tcp.', '_telnet._tcp.',
            '_whois._tcp.', '_h323cs._tcp.', '_h323cs._udp.',
            '_h323be._tcp.', '_h323be._udp.', '_h323ls._tcp.',
            '_https._tcp.', '_h323ls._udp.',
            '_sipinternal._tcp.', '_sipinternaltls._tcp.',
            '_sip._tls.', '_sipfederationtls._tcp.',
            '_jabber._tcp.',
            '_xmpp-server._tcp.', '_xmpp-client._tcp.',
            '_imap.tcp.', '_certificates._tcp.',
            '_crls._tcp.', '_pgpkeys._tcp.',
            '_pgprevokations._tcp.', '_cmp._tcp.',
            '_svcp._tcp.', '_crl._tcp.', '_ocsp._tcp.',
            '_PKIXREP._tcp.', '_smtp._tcp.', '_hkp._tcp.',
            '_hkps._tcp.', '_jabber._udp.', '_xmpp-server._udp.',
            '_xmpp-client._udp.', '_jabber-client._tcp.',
            '_jabber-client._udp.', '_kerberos.tcp.dc._msdcs.',
            '_ldap._tcp.ForestDNSZones.', '_ldap._tcp.dc._msdcs.',
            '_ldap._tcp.pdc._msdcs.', '_ldap._tcp.gc._msdcs.',
            '_kerberos._tcp.dc._msdcs.',
            '_kpasswd._tcp.', '_kpasswd._udp.', '_imap._tcp.']

        for srv_rd in srv_rds:
            domain_srv = '%s%s' % (srv_rd, domain)
            brt_srv = self.get_srv(domain_srv)[0]['Address']

            # /* show all brute srv records*/
            if verbose:
                print "[+] brute dns domain srv: \t%s\t:%s" % (
                    domain_srv, brt_srv)
            else:
                # /* only show valid record */
                if 0 < len(brt_srv):
                    print "[+] brute dns domain srv: \t%s\t:%s" % (
                        domain_srv, brt_srv)

            srv_ret.append({'Target': domain_srv,
                            'Type': 'brt_srv',
                            'Address': brt_srv})

            return srv_ret

    # /* brute domain gtld */
    def brute_gtld(self, domain, verbose=False):
        # /* save dns gtlds records */
        gtlds_ret = []

        gtlds = ['co', 'com', 'net', 'biz', 'org']

        for gtld in gtlds:
            domain_gtld = '%s.%s' % (domain, gtld)
            brt_gtld = self.get_a(domain_gtld)[0]['Address']

            # /* show all brute srv records*/
            if verbose:
                logging.debug("[+] brute dns domain gtld: \t%s\t:%s" % (
                    domain_gtld, brt_gtld))
            else:
                # /* only show valid record */
                if 0 < len(brt_gtld):
                    logging.debug("[+] brute dns domain gtld: \t%s\t:%s" % (
                        domain_gtld, brt_gtld))

            gtlds_ret.append({'Target': domain_gtld,
                              'Type': 'brt_gtld',
                              'Address': brt_gtld})

        return gtlds_ret

    # /* brute domain tld */
    def brute_tld(self, domain, verbose=False):
        # /* save dns tlds records */
        tlds_ret = []

        tlds = ['ac', 'ad', 'aeaero', 'af', 'ag', 'ai', 'al',
                'am', 'an', 'ao', 'aq', 'ar', 'arpa', 'as',
                'asia', 'at', 'au', 'aw', 'ax', 'az', 'ba',
                'bb', 'bd', 'be', 'bf', 'bg', 'bh', 'bi',
                'biz', 'bj', 'bm', 'bn', 'bo', 'br', 'bs',
                'bt', 'bv', 'bw', 'by', 'bzca', 'cat', 'cc',
                'cd', 'cf', 'cg', 'ch', 'ci', 'ck', 'cl',
                'cm', 'cn', 'co', 'com', 'coop', 'cr', 'cu',
                'cv', 'cx', 'cy', 'cz', 'de', 'dj', 'dk', 'dm',
                'do', 'dz', 'ec', 'edu', 'ee', 'eg', 'er', 'es',
                'et', 'eu', 'fi', 'fj', 'fk', 'fm', 'fo', 'fr',
                'ga', 'gb', 'gd', 'ge', 'gf', 'gg', 'gh', 'gi',
                'gl', 'gm', 'gn', 'gov', 'gp', 'gq', 'gr', 'gs',
                'gt', 'gu', 'gw', 'gy', 'hk', 'hm', 'hn', 'hr',
                'ht', 'hu', 'id', 'ie', 'il', 'im', 'in', 'info',
                'int', 'io', 'iq', 'ir', 'is', 'it', 'je', 'jm',
                'jo', 'jobs', 'jp', 'ke', 'kg', 'kh', 'ki', 'km',
                'kn', 'kp', 'kr', 'kw', 'ky', 'kz', 'la', 'lb',
                'lc', 'li', 'lk', 'lr', 'ls', 'lt', 'lu', 'lv',
                'ly', 'ma', 'mc', 'md', 'me', 'mg', 'mh', 'mil',
                'mk', 'ml', 'mm', 'mn', 'mo', 'mobi', 'mp', 'mq',
                'mr', 'ms', 'mt', 'mu', 'museum', 'mv', 'mw', 'mx',
                'my', 'mz', 'na', 'name', 'nc', 'ne', 'net', 'nf',
                'ng', 'ni', 'nl', 'no', 'np', 'nr', 'nu', 'nz', 'om',
                'org', 'pa', 'pe', 'pf', 'pg', 'ph', 'pk', 'pl', 'pm',
                'pn', 'pr', 'pro', 'ps', 'pt', 'pw', 'py', 'qa', 're',
                'ro', 'rs', 'ru', 'rw', 'sa', 'sb', 'sc', 'sd', 'se',
                'sg', 'sh', 'si', 'sj', 'sk', 'sl', 'sm', 'sn', 'so',
                'sr', 'st', 'su', 'sv', 'sy', 'sz', 'tc', 'td', 'tel',
                'tf', 'tg', 'th', 'tj', 'tk', 'tl', 'tm', 'tn', 'to',
                'tp', 'tr', 'travel', 'tt', 'tv', 'tw', 'tz', 'ua',
                'ug', 'uk', 'us', 'uy', 'uz', 'va', 'vc', 've', 'vg',
                'vi', 'vn', 'vu', 'wf', 'ws', 'ye', 'yt', 'za', 'zm',
                'zw']

        for tld in tlds:
            domain_tld = '%s.%s' % (domain, tld)
            brt_tld = self.get_a(domain_tld)[0]['Address']

            # /* show all brute srv records*/
            if verbose:
                print "[+] brute dns domain tld: \t%s\t:%s" % (
                    domain_tld, brt_tld)
                tlds_ret.append({'Target': domain_tld,
                                 'Type': '',
                                 'Address': brt_tld})
            else:
                # /* only show valid record */
                if 0 < len(brt_tld):
                    print "[+] brute dns domain tld: \t%s\t:%s" % (
                        domain_tld, brt_tld)

                tlds_ret.append({'Target': domain_tld,
                                 'Type': 'brt_tld',
                                 'Address': brt_tld})

        return tlds_ret

    # /* google search domain dns */
    def google_search(self, domain):
        print '[+] google search %s' % domain
        pass

    # /* output domain query information */
    def info(self, domain, threadnum, wordlist):
        logging.debug('[+]show  domain information')

        return {
            'wildcard': self.dns_wildcard(domain),
            'a': self.get_a(domain),
            'cname': self.get_cname(domain),
            'mx': self.get_mx(domain),
            'ns': self.get_ns(domain),
            'soa': self.get_soa(domain),
            'spf': self.get_spf(domain),
            'txt': self.get_txt(domain),
            'srv': self.get_srv(domain),
            'zone_transfer': self.zone_transfer(domain),
            'brute-domain': self.multi_brute_domain(domain,
                                                    threadnum,
                                                    wordlist),
            'brute-reverse-c': self.brute_reverse_c(domain),
            'brute_gtld': self.brute_gtld(domain),
            'brute_tld': self.brute_tld(domain)
        }

if __name__ == "__main__":

    dnsq = dnsinfo()
    # print dnsq.zone_transfer('demo.com')
    import json
    f = open('/home/notfound/share/json.txt', 'w')

    json.dump(
        dnsq.multi_brute_domain("skypixel.com", 20, '/opt/fuzzdb/discovery/subdomains-top1mil-20000.txt'), f)
    f.close()
