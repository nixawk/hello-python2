#!/usr/bin/python
# -*- coding: utf-8 -*-


def my_function(a, b):
    """Returns a * b

    >>> my_function(['A', 'B', 'C'], 3) #doctest: +NORMALIZE_WHITESPACE
    ['A', 'B', 'C',
     'A', 'B', 'C',
     'A', 'B', 'C']

    This does not match because of the extra space after the [ in the list

    >>> my_function(['A', 'B', 'C'], 2) #doctest: +NORMALIZE_WHITESPACE
    [ 'A', 'B', 'C',
      'A', 'B', 'C' ]
    """
    return a * b
