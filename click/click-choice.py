#!/usr/bin/python
# -*- coding: utf-8 -*-

import click


@click.command()
@click.option('--hash-type', default=False, type=click.Choice(['md5', 'sha256']))
def digest(hash_type):
    click.secho("%s hash" % hash_type, fg='red')


if __name__ == '__main__':
    digest()


## References

# http://click.pocoo.org/5/options/#choice-options