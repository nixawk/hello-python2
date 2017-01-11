#!/usr/bin/python
# -*- coding: utf-8 -*-

# BaseException
# Base class for all exceptions. Implements logic for creating a string
# representation of the exception using str() from the arguments passed to the
# constructor.

# Exception
# Base class for exceptions that do not result in quitting the running application.
# All user-defined exceptions should use Exception as a base class.

# StandardError
# Base class for built-in exceptions used in the standard library.

# ArithmeticError
# Base class for match-related errors.

# LookupError
# Base class for errors raised when something can't be found.

# EnvironmentError
# Basic class for errors that come from outside of Python (the operating, filesystem, etc.)


class CustomException(Exception):
    pass


if __name__ == '__main__':
    raise CustomException('This is a custom exception.')
