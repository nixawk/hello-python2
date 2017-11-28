#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
$ python click-group.py
Usage: click-group.py [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  dropdb
  initdb
  querydb
"""

# @cli.command() VS @click.command()

import click


@click.group()
def cli():
    pass


@cli.command()  
def querydb():
    click.echo('query database')


@click.command()
def initdb():
    click.echo('init database')


@click.command()
def dropdb():
    click.echo('drop database')


cli.add_command(initdb)
cli.add_command(dropdb)


if __name__ == '__main__':
    cli()


# Commands can be attached to other commands of type Group. This allows
# arbitrary nesting of scripts. 

# As you can see, the group() decorator works like the command() decorator,
# but creates a Group object instead which can be given multiple subcommands
# that can be attached with Group.add_command().