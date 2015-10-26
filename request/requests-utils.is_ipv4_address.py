#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests


print(requests.utils.is_valid_cidr("192.168.1.1"))
print(requests.utils.is_valid_cidr("192.168.1.1/24"))

print(requests.utils.is_ipv4_address("192.168.1.1"))
print(requests.utils.is_ipv4_address("192.168.1.1/24"))

print(requests.utils.address_in_network('192.168.1.1', '192.168.1.1/24'))
