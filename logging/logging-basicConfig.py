#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging

LOG_FILENAME = 'logging_example.out'
logging.basicConfig(filename=LOG_FILENAME,
                    level=logging.DEBUG)

logging.debug('This message should go to the log file')
