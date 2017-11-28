#!/usr/bin/python
# -*- coding: utf-8 -*-

import click


# Click supports launching applications through launch(). This can be used
# to open the default application assocated with a URL or filetype. This
# can be used to launch web browsers or picture viewers, for instance.
# In addition to this, it can also launch the file manager and automatically
# select the provided file.

click.launch("https://github.com/")
click.launch("/etc/passwd")
click.launch('/usr/bin/id')