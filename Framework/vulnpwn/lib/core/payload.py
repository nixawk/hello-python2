#!/usr/bin/python
# -*-  coding: utf-8 -*-

##
# Current source: https://github.com/open-security/vulnpwn/
##

from lib.base import module


class Payload(module.Module):
    def __init__(self):
        module.Module.__init__(self)
        self.shellcode = ''

    def generate_shellcode(self):
        pass

    def do_run(self, line):
        '''generate a payload shellcode'''
        self.generate_shellcode()
