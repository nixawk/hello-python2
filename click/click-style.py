#!/usr/bin/python
# -*- coding: utf-8 -*-


import click


click.echo(click.style('Hello World', fg='red'))
click.echo(click.style('Hello World', fg='green'))
click.echo(click.style('Hello World', fg='blue'))


# The combination of echo() and style() is also available in a single function called secho()

click.secho('Hello World', fg='yellow')
click.secho('Hello World', fg='white')
click.secho('Hello World', fg='red')