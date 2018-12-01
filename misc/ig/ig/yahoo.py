#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
import time
import lxml.etree
import randoms
import re
from searchengine import searchengine


class yahoo(searchengine):
    """Search resources from yahoo searchengine, include titles/urls."""
    def __init__(self):
        super(yahoo, self).__init__()

    def yahoo_dork_search(self, dork, page=0, random_sleep=True):
        """Search dorks from yahoo pages"""
        resources = []
        indexs = range(page + 1)
        for index in indexs:
            req = requests.Session()
            url = 'https://search.yahoo.com/search'
            headers = {'User-Agent': 'Mozilla/5.0'}
            pz = 10  # items num in per page
            params = {'pz': pz, 'p': dork, 'b': pz * index + 1}
            resp = req.get(url, params=params, headers=headers)
            if resp.status_code != 200:  # no available baidu pages
                return {dork: resources}

            html = lxml.etree.HTML(resp.text)
            ols = html.xpath('//div[@id="main"]/div/div[@id="web"]/'
                             'ol[contains(@class, "searchCenterMiddle")]')
            if not ols:
                return {dork: resources}  # no available baidu pages

            for ol in ols:
                as_ = ol.xpath('//h3[@class="title"]/a')
                for a in as_:
                    title = "".join([_ for _ in a.itertext()])
                    href = a.get('href')
                    href = self.parse_yahoo_url(href)
                    data = [title, href]
                    resources.append(data)

            # Avoid yahoo.com banning spider ip, sleep during 1...n (not 1, n)
            if random_sleep and len(indexs) > 1 and index != indexs[-1]:
                rt = randoms.rand_item_from_iters([_ for _ in range(1, 8)])
                print("sleeping {} s to avoid yahoo...".format(rt))
                time.sleep(int(rt))

        return {dork: resources}

    def parse_yahoo_url(self, url):
        """parse link from yahoo href"""
        if '/RU=' in url:  # parse
            # regex = re.compile('/RU=([^\']+)/RK=0')
            regex = re.compile('.*/RU=([^\']+)/RK=')
            url = regex.findall(url)[0]
        url = requests.utils.unquote(url)
        return url


def demo_yahoo():
    """A demo test for yahoo class"""
    yh = yahoo()
    dork = 'site:google.com'
    data = yh.yahoo_dork_search(dork, page=1)
    for title, href in data[dork]:
        print(title)
        print(href)
        print('\n-----------\n')


if __name__ == "__main__":
    demo_yahoo()
