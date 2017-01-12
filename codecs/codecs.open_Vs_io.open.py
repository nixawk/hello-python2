#!/usr/bin/python
# -*- coding: utf-8 -*-

import codecs
import io


# [io.open()] is a good choice for you.
# python3: open == io.open

def io_write():
    data = u'Привет мир'
    # encoding = 'utf-16'

    print(data)
    with io.open('io_testfile', 'w') as f:
        f.write(data)


def codecs_write():
    data = u'Привет мир'    # Please try (data = 'Привет мир'), it fails.
    encoding = 'utf-8'

    print(data)
    # UnicodeEncodeError: 'ascii' codec can't encode
    # characters in position 0-5: ordinal not in range(128)
    # with codecs.open('codecs_testfile', 'w') as f:

    # If an error encoding, or no encoding, it will make an error.
    with codecs.open('codecs_testfile', 'w', encoding=encoding) as f:
        f.write(data)


if __name__ == '__main__':
    io_write()
    codecs_write()
