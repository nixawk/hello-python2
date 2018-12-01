#!/usr/bin/python
# -*- coding: utf-8 -*-

from searchengine import searchengine
import requests
import time
import lxml.etree
import randoms


class netcraft(searchengine):
    def __init__(self):
        super(netcraft, self).__init__()

    def domain_search(self, domain, page=0, random_sleep=True):
        """Search domains from http://searchdns.netcraft.com/
        """
        domains = []
        last = ''
        indexs = range(page)
        for index in indexs:
            params = {'restriction': 'site+contains',
                      'host': '*.{}'.format(domain),
                      'from': index * 20 + 1,
                      'last': last}
            api_url = 'http://searchdns.netcraft.com/'
            headers = {'User-Agent': 'Mozilla/5.0'}
            resp = requests.get(api_url, params=params)

            html = lxml.etree.HTML(resp.text)
            a_s = html.xpath('//td[@align="left"]/a[@rel="nofollow"]')
            d_s = [requests.utils.urlparse(a.get('href')).netloc for a in a_s]
            if d_s:
                last = d_s[-1]
                domains.extend(d_s)

            if random_sleep and len(indexs) > 1 and index != indexs[-1]:
                rt = randoms.rand_item_from_iters([_ for _ in range(1, 8)])
                print("sleeping {} s to avoid baidu...".format(rt))
                time.sleep(int(rt))

        return domains


def demo_netcraft():
    from pprint import pprint
    domain = 'google.com'
    nt = netcraft()
    data = nt.domain_search(domain, page=3)
    pprint(data)


if __name__ == '__main__':
    demo_netcraft()
