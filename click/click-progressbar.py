#!/usr/bin/python
# -*- coding: utf-8 -*-

import click


with click.progressbar(range(1000000), label='Unzipping archive') as bar:
    for user in bar:
        pass


## References

# http://click.pocoo.org/5/utils/