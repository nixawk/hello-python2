
"""
Datetime

Additionally new style formatting allows objects to control their own rendering.
This for example allows datetime objects be formatted inline:
"""

from datetime import datetime


print '{:%Y-%m-%d %H:%M}'.format(datetime(2001, 2, 3, 4, 5))
