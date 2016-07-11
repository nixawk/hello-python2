#!/usr/bin/python
# -*- coding: utf-8 -*-

# Author: Nixawk
# Name:   bing api search
# Date:   Sat Sep 26 11:39:32 UTC 2015
# Docs:   https://datamarket.azure.com/dataset/bing/search

import requests
import json
import urllib
import logging


logging.basicConfig(level=logging.INFO, format="[+] %(message)s")
logger = logging.getLogger('bing_api_search')


class Bing(object):
    def __init__(self):
        """Get results from bing api
        """
        self.api_url = 'http://api.datamarket.azure.com/Bing/Search/Web'
        self.bing_urls = []
        self.bing_titles = []
        self.bing_results = []

    def json(self, content):
        """Json data format
        """
        logger.debug('translate data as json format')

        try:
            return json.loads(content)
        except ValueError:
            return {}

    def json_parse_Data(self, bing_json):
        """valid json data
        """
        logger.debug('if valid json data or not')
        if (bing_json) and ('d' in bing_json):
            return bing_json['d']

        return {}

    def json_parse_Results(self, bing_json_d):
        """parse results records from bing json data
        """
        logger.debug('parse results records from bing json data')
        if (bing_json_d) and ('results' in bing_json_d):
            return bing_json_d['results']

        return []

    def json_parse_Url(self, bing_json_r):
        """Parse url from (bing json results records)
        """
        logger.debug('parse urls from bing results records')
        return [_['Url'] for _ in bing_json_r if 'Url' in _]

    def json_parse_Title(self, bing_json_r):
        """Parse title from (bing json results records)
        """
        logger.debug('parse titles from bing results records')
        return [_['Title'] for _ in bing_json_r if 'Title' in _]

    def uniq(self, totalrecords=[], newrecords=[]):
        """uniq records
        """
        for i in newrecords:
            if i not in totalrecords:
                totalrecords.append(i)

        return totalrecords

    def api_request(self, url, api_key):
        """send api http request
        """
        sess = requests.Session()
        return sess.get(url, auth=("", api_key))

    def api_search(self, api_key, query, top=10, bing_limit=0):
        """bing search api
        """
        logger.debug('use bing search api for an new search')
        num = 1
        payload = {
            'Query': "'%s'" % query,
            '$format': 'json',
            '$top': top
        }

        while True:
            try:
                bing_json_d = None  # {'d':{}}
                bing_json_r = None  # {'d':{'results'}}

                url = "%s?%s" % (self.api_url, urllib.urlencode(payload))
                logger.info("%08d : %s" % (num, url))

                bing_resp = self.api_request(url, api_key)
                logger.info("%d - %s" % (bing_resp.status_code, url))

                # parse bing json data
                bing_json = self.json(bing_resp.text)
                bing_json_d = self.json_parse_Data(bing_json)

                # check if exists valid 'd' record
                if bing_json_d:
                    bing_json_r = self.json_parse_Results(bing_json_d)
                else:
                    break

                # check if exists valid ['d']['Results'] record
                if bing_json_r:
                    # parse results from json
                    self.uniq(self.bing_results, bing_json_r)

                    # parse urls from json
                    self.uniq(
                        self.bing_urls,
                        self.json_parse_Url(bing_json_r)
                    )

                    # parse titles from json
                    self.uniq(
                        self.bing_titles,
                        self.json_parse_Title(bing_json_r)
                    )
                else:
                    break

                # limit search number
                if (bing_limit != 0) and (bing_limit <= num):
                    break
                else:
                    num = num + (top * 1)

                if '__next' not in bing_json_d:
                    break
                else:
                    payload['$skip'] = num
            except KeyboardInterrupt:
                break

        return self.bing_results, self.bing_urls, self.bing_titles


if __name__ == "__main__":
    api_key = ''  # put your key here.
    query = 'site:exploit-db.com'

    bing = Bing()
    bing.api_search(api_key, query)

    # bing.api_search(api_key, query, top=5, bing_limit=100)
    #   api_key    :  bing search api key
    #   query      :  bing search syntax
    #   top        :  number of every query records
    #   bing_limit :  limit search records number

    for url in bing.bing_urls:
        print(url)
