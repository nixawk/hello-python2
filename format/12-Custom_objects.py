
"""
Custom objects

The above example works through the use of the __format__() magic method. You
can define custom format handling in your own objects by overriding this method
. This gives you comlete control over the format syntax used.
"""


class HAL9000(object):
    def __format__(self, format):
        if (format == 'open-the-bad-bay-doors'):
            return "I'm afraid I can't do that."
        return 'HAL 9000'


print '{:open-the-bad-bay-doors}'.format(HAL9000())
