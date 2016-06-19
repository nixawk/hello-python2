
"""
Signed numbers

By default only negative numbers are prefixed with a sign. This can be changed
of course.
"""

print '%+d' % (42, )
print '{:+d}'.format(42)

# Use a space character to indicate that negative numbers should be prefixed
# with a minus symbol and a leading space should be used for positive ones.

print '% d' % ((- 23), )
print '{: d}'.format((- 23))
print '{: d}'.format(42)

# New style formatting is also able to control the position of the sign symbol
# relative to the padding.

print '{:=5d}'.format((- 23))
