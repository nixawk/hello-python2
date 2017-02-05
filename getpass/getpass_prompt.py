#!/usr/bin/python
# -*- coding: utf-8 -*-

import getpass


p = getpass.getpass(prompt="What is our favorite color ?")
if p.lower() == 'blue':
    print('Right. off you go.')
else:
    print('Auuuuuugh!')
