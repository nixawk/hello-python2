#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
import time
import lxml.etree
import randoms
from searchengine import searchengine


class baidu(searchengine):
    """Search resources from Baidu searchengine, include titles/urls/bodys"""
    def __init__(self):
        super(baidu, self).__init__()

    def baidu_dork_search(self, dork, page=0, random_sleep=True):
        """Search dorks from baidu pages"""
        resources = []  # title, res_href, baidu_link
        indexs = range(page + 1)
        for index in indexs:
            req = requests.Session()
            url = 'http://www.baidu.com/s'
            headers = {'User-Agent': 'Mozilla/5.0'}
            params = {'pn': index * 10, 'wd': dork, 'ie': 'utf-8'}
            resp = req.get(url, params=params,
                           headers=headers, allow_redirects=False)
            if resp.status_code != 200:  # no available baidu pages
                return {dork: resources}

            html = lxml.etree.HTML(resp.text)
            divs = html.xpath('//div[contains(@class, "result c-container")]')
            if not divs:
                return {dork: resources}  # no available baidu pages

            for div in divs:
                hrefs = div.xpath('//div[@class="f13"]/a')
                titles = div.xpath('//h3[@class="t"]/a')

                for href, title in zip(hrefs, titles):
                    bd_title = "".join([_ for _ in title.itertext()])
                    bd_href = "".join([_ for _ in href.itertext()])
                    bd_link = href.get('href')
                    # print(bd_title, bd_href, bd_link)
                    data = [bd_title, bd_href, bd_link]
                    resources.append(data)

            # Avoid baidu.com banning spider ip, sleep during 1...n (not 1, n)
            if random_sleep and len(indexs) > 1 and index != indexs[-1]:
                rt = randoms.rand_item_from_iters([_ for _ in range(1, 8)])
                print("sleeping {} s to avoid baidu...".format(rt))
                time.sleep(int(rt))

        return {dork: resources}


def demo_baidu():
    """A demo test for baidu class"""
    bd = baidu()
    dork = 'site:google.com'
    data = bd.baidu_dork_search(dork, page=1)
    for title, href, link in data[dork]:
        print(title)
        print(href)
        print('\n-----------\n')


if __name__ == "__main__":
    demo_baidu()
