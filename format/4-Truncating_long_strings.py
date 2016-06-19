
"""
Truncating long strings

Inverse to padding it is also possible to truncate overly long values to a
sepcific number of characters.

The number behind a . in the format specifics the precision of the output. For
strings that means that the output is truncated to the specified length. In our
example this would be 5 characters.
"""

print '%.5s' % ('helloworld', )
print '{:.5s}'.format('helloworld')

print '%.*s' % (7, 'helloworld')
print '{:.{}}'.format('helloworld', 7)

print '{:10.{}}'.format('helloworld', 7)
print '{:<10.{}}'.format('helloworld', 7)
print '{:-<10.{}}'.format('helloworld', 7)
