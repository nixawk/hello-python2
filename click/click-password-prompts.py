#!/usr/bin/python
# -*- coding: utf-8 -*-

import click


@click.command()
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
def encrypt(password):
    click.echo("Encrypting password to %s" % password.encode('rot13'))


if __name__ == '__main__':
    encrypt()