#!/usr/bin/python
# -*- coding: utf-8 -*-


class Context(object):
    
    def __init__(self):
        print('__init__')

    def __enter__(self):
        """A context manager is enabled by the with statement, and the API involves two methods.
        The __enter__() method is run when execution flow enters the code block inside the with.
        """
        print('__enter__')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """When execution flow leaves the with block, the __exit__() method of the context manager
        is called to clean up any resources being used.
        """
        print('__exit__')

    def __del__(self):
        print('__del__')

    def hello(self, string):
        """hello string
        """
        print("hello {}".format(string))


if __name__ == '__main__':
    with Context() as contextobj:
        contextobj.hello('context')


# __init__
# __enter__
# hello context
# __exit__
# __del__