#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
import time
import lxml.etree
import randoms
from searchengine import searchengine


class bing(searchengine):
    """Search resources from Bing searchengine, include titles/urls/bodys"""
    def __init__(self):
        super(bing, self).__init__()

    def bing_dork_search(self, dork, page=0, random_sleep=True):
        """Search dorks from bing pages"""
        resources = []  # title, res_href, bing_link
        indexs = range(page + 1)
        for index in indexs:
            req = requests.Session()
            req.cookies['SRCHHPGUSR'] = 'NEWWND=0&NRSLT=50&SRCHLANG=&AS=1'
            url = 'https://www.bing.com/search'
            headers = {'User-Agent': 'Mozilla/5.0'}
            params = {'first': index, 'q': dork}
            resp = req.get(url, params=params,
                           headers=headers, allow_redirects=True)

            if resp.status_code != 200:  # no available bing pages
                return {dork: resources}

            html = lxml.etree.HTML(resp.text)
            ols = html.xpath('//ol[@id="b_results" and @role="main"]')

            if not ols:
                return {dork: resources}  # no available bing pages

            for ol in ols:
                a_xpath = '//li[@class="b_algo"]/div[@class="b_title"]/h2/a'
                as_ = ol.xpath(a_xpath)
                for a in as_:
                    title = "".join([_ for _ in a.itertext()])
                    href = a.get('href')
                    data = [title, href]  # title, url
                    resources.append(data)

            # Avoid bing.com banning spider ip, sleep during 1...n (not 1, n)
            if random_sleep and len(indexs) > 1 and index != indexs[-1]:
                rt = randoms.rand_item_from_iters([_ for _ in range(1, 8)])
                print("sleeping {} s to avoid bing...".format(rt))
                time.sleep(int(rt))

        return {dork: resources}


def demo_bing():
    """A demo test for bing class"""
    bi = bing()
    dork = 'site:google.com'
    data = bi.bing_dork_search(dork, page=1)
    for title, href in data[dork]:
        print(title)
        print(href)
        print('\n-----------\n')


if __name__ == "__main__":
    demo_bing()
