#!/usr/bin/python
# -*- coding: utf-8 -*-

import click


@click.command()
@click.option('--host', default='8.8.8.8', help='target host')
@click.option('--port', default=53, help='target port')
def scan(host, port):
    click.echo("scan %s:%s" % (host, port))


if __name__ == '__main__':
    scan()