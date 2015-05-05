#!/usr/bin/env python
# -*- coding: utf8 -*-


# https://docs.python.org/2/library/stdtypes.html#bltin-file-objects
# http://learnpythonthehardway.org/book/ex16.html

# file.close
# file.closed
# file.encoding
# file.errors
# file.fileno
# file.flush
# file.isatty
# file.mode
# file.name
# file.newlines
# file.next
# file.read
# file.readinto
# file.readline
# file.readlines
# file.seek
# file.softspace
# file.tell
# file.truncate
# file.write
# file.writelines
# file.xreadlines


def write_data(filename):
    with open(filename, 'w') as f:
        data = "AAAA"
        print "write %s to file" % data
        f.write(data)

        data = "BBBB"
        f.truncate(0)    # empty file
        print "write %s to file" % data
        f.write(data)    # close


def read_data(filename):
    f = open(filename, 'r')
    print "offset: %d" % f.tell()         # current location (read)
    print "read %s from file" % f.read()

    print "offset: %d" % f.tell()         # current location (read)
    f.seek(0)
    print "read %s from file" % f.read()

    if not f.closed:
        f.close()

if __name__ == "__main__":
    filename = '/tmp/tmp.txt'
    write_data(filename)
    read_data(filename)
