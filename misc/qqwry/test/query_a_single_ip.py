#!/usr/bin/python
# -*- coding: utf8 -*-

from qqwry import QQwry


if __name__ == "__main__":
    ip = '8.8.8.8'
    qqWry = QQwry('qqwry.dat')
    country, city = qqWry.ip_location(ip)
    print(ip)
    print(country)
    print(city)
