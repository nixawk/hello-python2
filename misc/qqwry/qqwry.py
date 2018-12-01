#!/usr/bin/python
# -*- coding: utf-8 -*

"""
QQWry is a binary file which contains ip-related locations information.
This module search it and get location information from it.

  Usage:

    >>> from qqwry import QQwry
    >>> qqWry = QQwry('qqwry.dat')
    >>> qqWry.ip_location('8.8.8.8')
    ...


  Note: pleaes get qqwry ip database from trust sources.
"""

import socket
from struct import unpack


class QQwry(object):
    def __init__(self, db_file):
        """
        self.data           # ip database content
        self.startindex     # start index
        self.lastindex      # last index
        self.count          # index count
        """

        with open(db_file, 'r') as dbf:
            self.data = dbf.read()
            self.startindex, self.lastindex = unpack('II', self.data[:8])
            self.count = (self.lastindex - self.startindex) / 7 + 1

    def dichotomy(self, data, kwd, begin, end, index):
        """dichotomy search"""
        if end - begin <= 1:
            return begin

        half = (begin + end) / 2

        i = index + half * 7
        tmp = unpack('I', data[i: i+4])[0]

        if kwd <= tmp:
            return self.dichotomy(data, kwd, begin, half, index)
        else:
            return self.dichotomy(data, kwd, half, end, index)

    def getstring(self, offset):
        """get country / city string"""
        gb2312_str = self.data[offset: self.data.find('\0', offset)]
        try:
            utf8_str = gb2312_str.decode('gb2312')
        except:
            utf8_str = ""
        return utf8_str

    def index(self, ip):
        """get ip index with ip offset"""
        return self.startindex + 7 * (
            self.dichotomy(self.data, unpack('!I', socket.inet_aton(ip))[0],
                           0, self.count - 1, self.startindex))

    def record(self, offset):
        """a record = [IP Start] + [IP Offset]"""
        return unpack('I', "%s\0" % self.data[offset: offset + 3])[0]

    def country_redirect(self, offset):
        """record redirect"""
        byte = ord(self.data[offset])

        if byte == 1 or byte == 2:
            return self.country_redirect(self.record(offset + 1))
        else:
            return self.getstring(offset)

    def country_city(self, offset, ip=0):
        """get country / city from a record"""
        byte = ord(self.data[offset])

        if byte == 1:
            return self.country_city(self.record(offset+1))

        elif byte == 2:
            return (self.country_redirect(self.record(offset+1)),
                    self.country_redirect(offset+4))
        else:
            return (self.getstring(offset),
                    self.country_redirect(self.data.find('\0', offset) + 1))

    def ip_file(self, ipfile):
        """get multi ips locations in a file"""
        with open(ipfile) as f:
            for i in f:
                yield i.strip()

    def ip_location(self, ip):
        """get a single ip location"""
        (country, city) = self.country_city(
            self.record(self.index(ip) + 4) + 4)
        return (country, city)
