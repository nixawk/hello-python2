#!/usr/bin/env python

import itertools
import string
import sys


def usage():
    print "Password generator - v1.0 "
    print "\t%s [type] [length]" % sys.argv[0]
    print "\ttype: l for letters, d for digits, s for singals"


def generator(lsttype, length):
    """
    generator passwords with letters and signals
    Create by hap.ddup@gmail.com
    """
    pass_lst = []
    chars = {'l': list(string.letters),
             'd': list(string.digits),
             's': list("#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ")
             }

    for i in lsttype:
        try:
            pass_lst.extend(chars[i])
        except KeyError:
            usage()
            sys.exit(1)

    for i in itertools.product(pass_lst, repeat=length):
        print "".join(i)

if __name__ == '__main__':
    if sys.argv.__len__() != 3:
        usage()
    else:
        generator(sys.argv[1], int(sys.argv[2]))
