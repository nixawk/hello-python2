#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import time
import sys


"""
CRITICAL  ---- 50
ERROR     ---- 40
WARNING   ---- 30
INFO      ---- 20
DEBUG     ---- 10
NOTSET    ---- 0
"""

LEVEL_ST = 21
LEVEL_ND = 22
LEVEL_RD = 23

logging.addLevelName(LEVEL_ST, "FIRST LEVEL")
logging.addLevelName(LEVEL_ND, 'SECOND LEVEL')
logging.addLevelName(LEVEL_RD, 'THIRD LEVEL')

logger = logging.getLogger('sqlmapLog')

# handler = None
handler = logging.StreamHandler(sys.stdout)

formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s",
                              "%a, %d %b %Y %H:%M:%S")

handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

i = 0

while True:
    i = i + 1
    logger.info('number is %d' % i)

    time.sleep(1)
