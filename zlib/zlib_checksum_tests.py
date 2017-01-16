#!/usr/bin/python
# -*- coding: utf-8 -*-

import timeit


iterations = 1000


def show_results(title, result, iterations):
    "Print results in terms of microseconds per pass and per item."
    per_pass = 1000000 * (result / iterations)
    print '%s:\t%.2f usec/pass' % (title, per_pass)


adler32 = timeit.Timer(
    stmt='zlib.adler32(data)',
    setup="import zlib; data=open('/etc/passwd', 'r').read() * 10"
)
show_results('Adler32, separate', adler32.timeit(iterations), iterations)

adler32_running = timeit.Timer(
    stmt='zlib.adler32(data, cksum)',
    setup="import zlib; data=open('/etc/passwd', 'r').read() * 10; cksum = zlib.adler32(data)"
)
show_results('Adler32, running', adler32_running.timeit(iterations), iterations)

crc32 = timeit.Timer(
    stmt='zlib.crc32(data)',
    setup="import zlib; data=open('/etc/passwd', 'r').read() * 10"
)
show_results('CRC-32, separate', crc32.timeit(iterations), iterations)

crc32_running = timeit.Timer(
    stmt='zlib.crc32(data, cksum)',
    setup="import zlib; data=open('/etc/passwd', 'r').read() * 10; cksum = zlib.crc32(data)"
)
show_results('CRC-32, running', crc32_running.timeit(iterations), iterations)
