#!/usr/bin/python
# -*- coding: utf-8 -*-

import getpass
import sys


# By default, getpass() uses stdout to print the prompt string.
# For a program which may produce useful output on sys.stdout, it is
# frequently better to send the prompt to another stream such as sys.stderr.

p = getpass.getpass(stream=sys.stderr)
print('You entered: {}'.format(p))
