
"""
Named placeholders
"""

data = {'first': 'Hodor', 'last': 'Hodor!'}
print '%(first)s %(last)s' % data

print '{first} {last}'.format(**data)
# Error: print '{first} {last}'.format(data)
