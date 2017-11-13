#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
import json
import logging


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# Limit: 
#   Requests per day                  10,000
#   Requests per 100 seconds per user 3,000   

def google_safe_browsing_lookup(api_key, urls):
    api = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    params = {'key': "{API_KEY}".format(API_KEY=api_key)}

    headers = {
        'Content-Type' : "application/json",
        'User-Agent'   : "Mozilla/5.0"
    }

    threat_entries = [{'url': url_} for url_ in urls]

    data =   {
        "client": {
          "clientId":      "Python SafeBrowsing Client",
          "clientVersion": "4.0.0"
        },
        "threatInfo": {
          "threatTypes"      : ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          "platformTypes"    : ["ANY_PLATFORM"],
          "threatEntryTypes" : ["URL"],
          "threatEntries"    : threat_entries
        }
    }

    log.debug('URLs: %s', urls)
    response = requests.post(api, params=params, headers=headers, json=data)
    log.debug('Status Code: %d', response.status_code)
    log.info(response.json())

    return response.json()


if __name__ == '__main__':
    api_key = ''  # Set up an API key
    urls = [
        "http://0nilneamazon.com/",
        "http://114oldest.com",
        "http://188.241.140.222",
        "http://18xn.com",
        "http://195.20.41.233",
        "http://1stand2ndmortgage.com",
        "http://203.170.193.23",
        "http://209.164.84.70",
        "http://222.29.197.232",
    ]
    resp = google_safe_browsing_lookup(api_key, urls)
    print(resp)


## References
# https://developers.google.com/safe-browsing/v4/get-started
# https://developers.google.com/apis-explorer/?hl=en_US#p/safebrowsing/v4/
# https://developers.google.com/safe-browsing/v4/reference/rest/v4/ThreatType

