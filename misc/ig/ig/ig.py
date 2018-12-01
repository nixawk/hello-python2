#!/usr/bin/python
# -*- coding: utf-8 -*-

from optparse import OptionParser
from optparse import OptionGroup
from optparse import OptionError
import sys
from idns import idns
from webspider_domain import baidu_domain_spider
from webspider_domain import bing_domain_spider
from webspider_domain import yahoo_domain_spider
from webspider_domain import google_domain_spider
from webspider_domain import netcraft_domain_spider
from webspider_domain import zoomeye_domain_spider
from webspider_domain import censys_domain_spider
from webspider_domain import github_domain_spider
from bruteforce_domain import idns_bruteforce
from pprint import pprint


class cmdline(object):
    def getArgs(self):
        """This function parses the command line parameters and arguments.
        """
        usage = "python %prog [options]"
        parser = OptionParser(usage=usage)
        try:
            domainopt = OptionGroup(parser, "DOMAIN INFORMATION",
                                    "scan domains/subdomains information")
            domainopt.add_option('-d', '--domain', dest='domain', type='str',
                                 help='domain name')
            domainopt.add_option('--query_a', action='store_true',
                                 help='query dns A records')
            domainopt.add_option('--query_cname', action='store_true',
                                 help='query dns CNAME records')
            domainopt.add_option('--query_mx', action='store_true',
                                 help='query dns MX records')
            domainopt.add_option('--query_ns', action='store_true',
                                 help='query dns NS records')
            domainopt.add_option('--query_soa', action='store_true',
                                 help='query dns SOA records')
            domainopt.add_option('--query_srv', action='store_true',
                                 help='query dns SRV records')
            domainopt.add_option('--query_txt', action='store_true',
                                 help='query dns TXT records')
            domainopt.add_option('--query_axfr', action='store_true',
                                 help='query dns AXFR records')
            domainopt.add_option('--enable_wildcard', action='store_true',
                                 help='check if dns wildcard exists (default: disable)')
            domainopt.add_option('--bruteforce', action='store_true',
                                 help='brute force subdomains')
            domainopt.add_option('--wordlist', dest='wordlist', type='str',
                                 help='wordlist for subdomains bruteforce')
            domainopt.add_option('--pages', dest='pages', type='int',
                                 help='pages number to spider')
            domainopt.add_option('--sleep', action='store_true',
                                 help='enable sleep to bypass spider ban')
            domainopt.add_option('--baidu', action='store_true',
                                 help='search domains from baidu.com')
            domainopt.add_option('--bing', action='store_true',
                                 help='search domains from bing.com')
            domainopt.add_option('--google', action='store_true',
                                 help='search domains from google.com')
            domainopt.add_option('--yahoo', action='store_true',
                                 help='search domains from yahoo.com')
            domainopt.add_option('--censys', action='store_true',
                                 help='search domains from censys.io')
            domainopt.add_option('--censys_uid', dest='censys_uid',
                                 help='a censys api id')
            domainopt.add_option('--censys_secret', dest='censys_secret',
                                 help='a censys api secret')
            domainopt.add_option('--github', action='store_true',
                                 help='search domains from github.com')
            domainopt.add_option('--netcraft', action='store_true',
                                 help='search domains from netcraft.com')
            domainopt.add_option('--zoomeye', action='store_true',
                                 help='search domains from zoomeye.org')
            domainopt.add_option('--zoomeye_username', dest='zoomeye_username',
                                 type='str', help='a zoomeye username')
            domainopt.add_option('--zoomeye_password', dest='zoomeye_password',
                                 type='str', help='a zoomeye password')
            parser.add_option_group(domainopt)

            (args, _) = parser.parse_args()
        except (OptionError, TypeError) as e:
            parser.error(e)
        else:
            return args



def main():
    """parse cmdline options
    """
    c = cmdline()
    args = c.getArgs()

    domains = []  # save all domains result
    if not args.domain:
        print('[!] please a domain to scan subdomains, ex: google.com')
        sys.exit(0)

    domain = args.domain
    dnsqry = idns()

    result = {}
    result[domain] = {}

    if args.query_a:
        data = dnsqry.query_A(domain)
        result[domain].update(data[domain])

    if args.query_cname:
        data = dnsqry.query_CNAME(domain)
        result[domain].update(data[domain])

    if args.query_mx:
        data = dnsqry.query_MX(domain)
        result[domain].update(data[domain])

    if args.query_ns:
        data = dnsqry.query_NS(domain)
        result[domain].update(data[domain])

    if args.query_soa:
        data = dnsqry.query_SOA(domain)
        result[domain].update(data[domain])

    if args.query_srv:
        data = dnsqry.query_SRV(domain)
        result[domain].update(data[domain])

    if args.query_txt:
        data = dnsqry.query_TXT(domain)
        result[domain].update(data[domain])

    if args.query_axfr:  # If no axfr records, pleae try to read query_AXFR code
        try:
            data = dnsqry.query_AXFR(domain)
        except Exception as err:
            import traceback
            traceback.print_exc(err)
        result[domain].update(data[domain])

    if args.enable_wildcard:
        dnsqry.dns_wildcard(domain)

    if args.bruteforce:
        print('[!] bruteforce domain may cost long time')
        if args.wordlist:
            idns_bt = idns_bruteforce(domain, subdomains_wd=args.wordlist)
        else:
            print('[!] use default wordlist to bruteforce subdomains')
            idns_bt = idns_bruteforce(domain)
        idns_bt.work()
        idns_btret = []
        for item in idns_bt.domains:
            idns_btret.extend(item.keys())
        domains.extend(idns_btret)

        # merge domain bruteforce records
        result[domain].update({'BRUTEFORCE': domains})
        # pprint(idns_btret)

    # if not args.pages:
    #     print('[!] please set pages num to spider domains from searchengine')
    #     sys.exit(0)

    # default search pages: 1
    pages = args.pages if args.pages else 1

    sleep = True if args.sleep else False

    if args.baidu:
        print('[*] search domains from baidu.com')
        bd = baidu_domain_spider()
        bdret = bd.baidu_domain_search(domain, page=pages, random_sleep=sleep)
        domains.extend(bdret[domain]['baidu'])
        result[domain].update({'BAIDU': bdret[domain]['baidu']})

    if args.bing:
        print('[*] search domains from bing.com')
        bi = bing_domain_spider()
        biret = bi.bing_domain_search(domain, page=pages, random_sleep=sleep)
        domains.extend(biret[domain]['bing'])
        result[domain].update({'BING': biret[domain]['bing']})

    if args.google:
        print('[*] search domains from google.com')
        gg = google_domain_spider()
        ggret = gg.google_domain_search(domain, pages=pages, random_sleep=sleep)

        domains.extend(ggret[domain]['google'])
        result[domain].update({'GOOGLE': ggret[domain]['google']})

    if args.yahoo:
        print('[*] search domains from yahoo.com')
        yh = yahoo_domain_spider()
        yhret = yh.yahoo_domain_search(domain, page=pages, random_sleep=sleep)
        domains.extend(yhret[domain]['yahoo'])
        result[domain].update({'YAHOO': yhret[domain]['yahoo']})

    if args.censys:
        print('[*] search domains from censys.io')
        uid = args.censys_uid
        secret = args.censys_secret
        assert (uid and secret)

        cs = censys_domain_spider(uid, secret)
        csret = cs.censys_domain_search(domain, page=2)
        domains.extend(csret[domain]['censys'])
        result[domain].update({'CENSYS': csret[domain]['censys']})

    if args.github:
        print('[*] search domains from github.com')
        gh = github_domain_spider()
        # domain = 'google.com'
        ghret = gh.github_domain_search(domain)
        domains.extend(ghret[domain]['github'])
        result[domain].update({'GITHUB': ghret[domain]['github']})

    if args.netcraft:
        print('[*] search domains from netcraft.net')
        nt = netcraft_domain_spider()
        ntret = nt.netcraft_domain_search(domain, page=pages,
                                          random_sleep=sleep)
        domains.extend(ntret[domain]['netcraft'])
        result[domain].update({'NETCRAFT': ntret[domain]['netcraft']})

    if args.zoomeye:
        print('[*] search domains from zoomeye.org')
        zoomeye_user = args.zoomeye_username
        zoomeye_pass = args.zoomeye_password
        assert (zoomeye_user and zoomeye_pass)

        zms = zoomeye_domain_spider(zoomeye_user, zoomeye_pass)
        zmret = zms.zoomeye_domain_search(domain)
        domains.extend(zmret[domain]['zoomeye'])
        result[domain].update({'ZOOMEYE': zmret[domain]['zoomeye']})

    print('[+] all domains as follow:')
    pprint(domains)

    print('[+] all domains records:')
    print(result)

    return domains, result


if __name__ == '__main__':
    try:
        main()
    except Exception as err:
        print(err)
