
"""
Padding and aligning strings

By default values are formatted to take up only as many characters as needed to
represent the content. It is however also possible to define that a value should
be padded to a specific length.

Unfortunately the default alignment differs between old and new style formatting.
The old style defaults to right aligned while for new style it's left.
"""

# Align right:
print '%10s' % ('test', )
print '{:>10s}'.format('test')

# Align left
print '%-10s' % ('test', )
print '{:<10s}'.format('test')
print '{:10s}'.format('test')

# Align center
print '{:^10s}'.format('test')
print '{:-^10s}'.format('test')

# By argument
# In the previous example, the value '10' is encoded as part of the format string.
# However, it is possible to also supply values as argument.

print '%*s' % ((-8), 'test')
print '{:<{}s}'.format('test', 8)
