#!/usr/bin/python
# -*- coding: utf-8 -*-

import click


@click.command()
@click.option('--name', default="python", help="The name of your application")
def hello(name):
    click.echo("hello %s" % name)


if __name__ == '__main__':
    hello()


# Why does this example use echo() instead of the regular print() function?
# The answer to this question is that Click attempts to support both Python 2
# and Python 3 the same way and to be very robust even when the environment
# is misconfigured. Click wants to be functional at least on a basic leve
# even if everything is completely broken.

# What this means is that the echo() function applies some error correction
# in case the terminal is misconfigured instead of dying with an UnicodeError.

# As an added benefit, starting with Click 2.0, the echo function also has good
# support for ANSI colors. It will automatically strip ANSI codes if the output
# stream is a file and if colorama is supported, ANSI colors will also work on
# Windows. See ANSI Colors for more information.