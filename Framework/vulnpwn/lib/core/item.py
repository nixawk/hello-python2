#!/usr/bin/python
# -*-  coding: utf-8 -*-

##
# Current source: https://github.com/open-security/vulnpwn/
##


class Items(dict):
    """Core Options Items"""
    def __init__(self, *args, **kwargs):
        super(Items, self).__init__(*args, **kwargs)
        self.__dict__ = self
