#!/usr/bin/python
# -*- coding: utf-8 -*-


from functools import wraps



def handle_ctrl_c(func):
    """ctrl^c decorator.
    """
    @wraps(func)
    def wrapper(*args, **kwds):
        try:
            return func(*args, **kwds)
        except KeyboardInterrupt:
            pass
    return wrapper


@handle_ctrl_c
def print_input():
    """print input string.
    """
    print(raw_input("> "))


if __name__ == '__main__':
    print(print_input.__name__)
    print(print_input.__doc__)
    print_input()
