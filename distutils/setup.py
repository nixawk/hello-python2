#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
References:

    https://docs.python.org/2.7/distutils/index.html
    https://docs.python.org/2/distributing/index.html
    https://docs.python.org/2/distutils/setupscript.html
    https://packaging.python.org/en/latest/distributing/
    http://pythonhosted.org/setuptools/setuptools.html

"""

from disutils.core import setup


setup(name='Demo',
      version='1.0',
      description='Python Distribution Utilities',
      author='Python.Developer',
      author_email='demo@python.net',
      url='https://www.python.org/sigs/distutils-sig/',
      py_modules=['demo'],
      license='MIT'
      )

"""
Package Command:

    $ python setup.py sdist
"""
