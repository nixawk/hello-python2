#!/usr/bin/python
# -*- coding: utf-8 -*-

# http://stackoverflow.com/questions/519633/lazy-method-for-reading-big-file-in-python


def read_in_chunks(file_object, chunk_size=1024):
    """Lazy function (generator) to read a file piece by piece.
    Default chunk size: 1k."""

    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data


def read_in_line(file_object):
    for line in file_object:
        print(line)


if __name__ == "__main__":
    big_file = "/tmp/bigfile"
    with open(big_file) as f:
        for piece in read_in_chunks(f):
            print(piece)
