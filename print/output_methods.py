#!/usr/bin/env python
# -*- coding: utf-8 -*-

import traceback


class Output(object):

    def __init__(self):
        self.colorN = '\033[m'    # native
        self.colorR = '\033[31m'  # red
        self.colorG = '\033[32m'  # green
        self.colorB = '\033[34m'  # blue
        self.colorO = '\033[33m'  # orange

        self.global_options = {
            'debug': False,
            'verbose': False
        }

    def error(self, line):
        print('%s[!]%s %s' % (self.colorR, line, self.colorN))

    def output(self, line):
        print('%s[*]%s %s' % (self.colorB, self.colorN, line))

    def alert(self, line):
        print('%s[*]%s %s' % (self.colorG, self.colorN, line))

    def verbose(self, line):
        if self.global_options['verbose']:
            self.output(line)

    def debug(self, line):
        if self.global_options['debug']:
            self.output(line)

    def print_exception(self, line=''):
        if self.global_options['debug']:
            traceback.print_exc()

        self.error(line)

if __name__ == "__main__":
    op = Output()
    op.debug("debug information")
    op.output("output normal information")
    op.verbose("verbose information")
    op.error('error information')

    # enable debug / verbose mode
    op.global_options['debug'] = True
    op.global_options['verbose'] = True

    print('')

    op.debug("debug information")
    op.output("output normal information")
    op.verbose("verbose information")
    op.error('error information')
