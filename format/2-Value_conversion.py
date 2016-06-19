
"""
Value conversion

The new-style simple formatter calls by default the __format__() method of an
object for its representation. If you just want to render the output of str(..)
or repr(...) you can use the !s or !r conversion flags.

In %s-style you usually use %s for the string representation but there is %r for
repr(...) conversion.
"""

class Data(object):
    def __str__(self):
        return 'str'

    def __repr__(self):
        return 'repr'


print '%s %r' % (Data(), Data())
print '{0!s} {0!r}'.format(Data())
print '{!s} {!r}'.format('hello', 'world')

# In Python 3 there exists an additional conversion flag that uses the output of
# repr(...) but uses ascii(...) instead.

# Refer: https://pyformat.info
