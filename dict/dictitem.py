#!/usr/bin/env python
# -*- encoding: utf-8 -*-


class dict2(dict):
    def __init__(self, *args, **kwargs):
        super(dict2, self).__init__(*args, **kwargs)
        self.__dict__ = self


if __name__ == '__main__':
    from pprint import pprint

    item = dict2()
    item.value = "Hello World"

    pprint(item)
