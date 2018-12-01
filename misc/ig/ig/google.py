#!/usr/bin/env python
# -*- coding: utf-8 -*-

from searchengine import searchengine
import requests
import time
import lxml.etree
import randoms


class google(searchengine):
    """Search resources from Google searchengine, include titles/urls/bodys"""
    def __init__(self):
        super(google, self).__init__()

    def google_dork_search(self, dork, page=0, random_sleep=True):
        """Search dorks from google pages"""
        resources = []
        indexs = range(page + 1)
        for index in indexs:
            req = requests.Session()
            url = 'https://www.google.com/search'
            headers = {'User-Agent': 'Mozilla/5.0'}
            params = {'q': dork, 'start': index * 10,
                      'filter': 0, 'ie': 'UTF-8'}
            resp = req.get(url, params=params, headers=headers)
            if resp.status_code != 200:
                return {dork: resources}

            html = lxml.etree.HTML(resp.text)
            h3s = html.xpath('//h3[@class="r"]')
            if not h3s:
                return {dork: resources}

            for h3 in h3s:
                a = h3.xpath('./a')[0]
                gg_link = a.get('href')
                gg_href = gg_link[7:gg_link.find('&sa')]
                gg_title = ''.join([_ for _ in a.itertext()])
                data = [gg_title, gg_href, gg_link]
                resources.append(data)

            if random_sleep and len(indexs) > 1 and index != indexs[-1]:
                rt = randoms.rand_item_from_iters([_ for _ in range(1, 8)])
                print("sleeping {} s to avoid google...".format(rt))
                time.sleep(int(rt))

        return {dork: resources}


def demo_google():
    """A demo test for google class"""
    gg = google()
    dork = 'site:google.com'
    print(gg.google_dork_search(dork, page=0))


if __name__ == "__main__":
    demo_google()
