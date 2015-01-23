#!/usr/bin/env python
# -*- encoding: utf-8 -*-

# import abc
from abc_base import PluginBase


class RegisteredImplementation(object):
    def load(self, input):
        return input.read()

    def save(self, output, data):
        return output.write(data)

PluginBase.register(RegisteredImplementation)

if __name__ == "__main__":
    print 'Subclass:', issubclass(RegisteredImplementation, PluginBase)
    print 'Instance:', isinstance(RegisteredImplementation(), PluginBase)
    import pdb
    pdb.set_trace()
