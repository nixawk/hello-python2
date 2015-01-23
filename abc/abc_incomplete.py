#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from abc_base import PluginBase


class IncompleteImplementation(PluginBase):

    def save(self, output, data):
        return output.write(data)

PluginBase.register(IncompleteImplementation)

if __name__ == "__main__":
    print 'Subclass:', issubclass(IncompleteImplementation, PluginBase)
    print 'Instance:', isinstance(IncompleteImplementation(), PluginBase)
