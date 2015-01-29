#!/usr/bin/env python
# -*- coding: utf-8 -*-

from optparse import OptionParser
from optparse import OptionGroup
from optparse import OptionError


class cmdline(object):
    def getArgs(self):
        """
        This function parses the command line parameters and arguments
        """
        usage = "python %prog [options]"

        parser = OptionParser(usage=usage)

        try:
            parser.add_option('--version',
                              dest='showversion',
                              action='store_true',
                              help="Show program's version number and exit")

            target = OptionGroup(parser, "TARGET", "a domain, or a ip")

            target.add_option('-d', '--domain',
                              dest='domain',
                              type='str',
                              help='domain name')

            target.add_option('-i', '--ip',
                              dest='ipaddr',
                              help='target host ip')

            parser.add_option_group(target)

            option = parser.get_option('--version')
            option._short_opts = ['-version']
            option._long_opts = []

            (args, _) = parser.parse_args()

        except (OptionError, TypeError) as e:
            parser.error(e)
        else:
            return args


if __name__ == '__main__':
    c = cmdline()
    c.getArgs()
