#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests

# https://api.github.com/events
def github(username, password):
    return requests.get('https://api.github.com/user',
                        auth=(username, password))
