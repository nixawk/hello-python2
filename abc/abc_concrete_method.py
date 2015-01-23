#!/usr/bin/env python
# -*- encoding: utf-8 -*-


import abc
from cStringIO import StringIO


class ABCWithConcreteImplementation(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def retrieve_values(self, input):
        print 'base class reading data'
        return input.read()


class ConcreteOverride(ABCWithConcreteImplementation):

    def retrieve_values(self, input):
        base_data = super(ConcreteOverride, self).retrieve_values(input)
        print 'subclass sorting data'

        response = sorted(base_data.splitlines())
        return response


if __name__ == '__main__':
    input = StringIO("""line one
line two
line three""")

    reader = ConcreteOverride()
    print reader.retrieve_values(input)
