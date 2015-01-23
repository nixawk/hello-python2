#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from abc_base import PluginBase


class SubclassImplementation(PluginBase):

    def load(self, input):
        return input.read()

    def save(self, output, data):
        return output.write(data)


if __name__ == "__main__":
    print 'Subclass:', issubclass(SubclassImplementation, PluginBase)
    print 'Instance:', isinstance(SubclassImplementation(), PluginBase)
    import pdb
    pdb.set_trace()
