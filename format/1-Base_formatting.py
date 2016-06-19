
"""
Basic formatting

Simple positional formatting is probably the most common use-case. Use it if
the order of your argument is not likely to change and you only have few
elements you want to concatenate.

Since the elements are not represented by something as descriptive as a name
this simple style should only be used to format a relatively small number of elements.

"""

print '%s %s' % ('one', 'two')
print '{} {}'.format('one', 'two')

print '%d %d' % (1, 2)
print '{} {}'.format(1, 2)

# With new style formatting it is possible (and in Python 2.6 even mandatory) to
# give placeholders an explicit positional index.

print '{1} {0}'.format(1, 2)
