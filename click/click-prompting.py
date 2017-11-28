#!/usr/bin/python
# -*- coding: utf-8 -*-


import click


@click.command()
@click.option('--name', prompt=True)
def hello(name):
    click.echo('Hello %s!' % name)


if __name__ == '__main__':
    hello()