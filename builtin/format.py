#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
format(value[, format_spec])
    or
value.__format__(format_spec)
    or
'format' % value

# ###
https://docs.python.org/2/library/string.html#formatspec
http://www.tutorialspoint.com/python/python_strings.htm

format_spec ::=  [[fill]align][sign][#][0][width][,][.precision][type]
fill        ::=  <any character>
align       ::=  "<" | ">" | "=" | "^"
sign        ::=  "+" | "-" | " "
width       ::=  integer
precision   ::=  integer
type        ::=  "b" | "c" | "d" | "e" | "E" | "f" | "F" | "g" | "G" | "n" | "o" | "s" | "x" | "X" | "%"

++++++++++++++++++++++++++++++++
"""

print '{:e}'.format(10)
print '{:E}'.format(10)
print '{:f}'.format(10)
print '{:F}'.format(10)
print '{:g}'.format(10)
print '{:G}'.format(10)
print '{:%}'.format(10)
print '{:n}'.format(10)

print '{:s}'.format('X')
print '{:*>10s}'.format('X')
print '{:*^10s}'.format('X')
print '{:*<10s}'.format('X')
print '{:0<+10}'.format(2)
print '{:0<-10}'.format(2)

coord = (3, 5)
print 'X: {coord[0]}, Y:{coord[1]}'.format(coord=coord)

print '%c' % 12   # character
print '%s' % 12   # string conversion via str() prior to formatting
print '%i' % 12   # signed decimal integer
print '%d' % 12   # signed decimal integer
print '%o' % 12   # octal integer
print '%x' % 12   # hexadecimal integer (lowercase letters)
print '%X' % 12   # hexadecimal integer (uppercase letters)
print '%e' % 12   # exponential notation (with lowercase 'e')
print '%E' % 12   # exponential notation (with uppercase 'E')
print '%f' % 12   # floating point real number
print '%g' % 12   # the shorter of %f and %e
print '%G' % 12   # the shorter of %f and %E

print '%(name)s:%(score)06.1f' % {'score': 9.5, 'name': 'newsim'}
