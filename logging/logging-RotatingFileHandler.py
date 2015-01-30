#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import logging.handlers


LOG_FILENAME = 'logging_rotatingfile_example.out'

# Set up a specific logger with our desired output level
logger = logging.getLogger('Logger')
logger.setLevel(logging.DEBUG)

# Add the log message handler to the logger
handler = logging.handlers.RotatingFileHandler(LOG_FILENAME,
                                               maxBytes=20,
                                               backupCount=5)

logger.addHandler(handler)

# Log some messages
for i in range(50):
    logger.debug('message: %d' % i)
