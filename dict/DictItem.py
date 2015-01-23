#!/usr/bin/env python
# -*- encoding: utf-8 -*-


import collections


class DictItem(collections.MutableMapping):
    """A dictionary that applies an arbitrary key-altering
    function before accessing the keys"""

    def __init__(self, *args, **kwargs):
        self.item = dict()
        self.update(dict(*args, **kwargs))

    def __getitem__(self, key):
        return self.item[self.__keychange__(key)]

    def __setitem__(self, key, value):
        self.item[self.__keychange__(key)] = value

    def __delitem__(self, key):
        del self.item[self.__keychange__(key)]

    def __iter__(self):
        return iter(self.item)

    def __len__(self):
        return len(self.item)

    def __keychange__(self, key):
        return key


class demo(DictItem):

    def __keychange__(self, key):
        return key.lower()

if __name__ == "__main__":
    aa = demo(Name='smith', Sex='gentle')

    from pprint import pprint
    pprint(aa.items())
