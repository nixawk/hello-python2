#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import sys

# logging.Handler(self, level=0)
# logging.FileHandler(self, filename, mode='a', encoding=None, delay=0)
# logging.NullHandler(self, level=0)
# logging.StreanHandler(self, stream=None)


def file_logger(filename, level):

    level = level or logging.INFO

    logger = logging.getLogger(__name__)
    logger.setLevel(level)

    handler = logging.FileHandler(filename)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


def stream_logger(stream, level):

    stream = stream or sys.stdout
    level = level or logging.INFO

    logger = logging.getLogger(__name__)
    logger.setLevel(level)

    handler = logging.StreamHandler(stream=stream)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


if __name__ == "__main__":
    floger = file_logger('aaaaaa.log', logging.DEBUG)
    sloger = stream_logger(sys.stdout, logging.DEBUG)

    for i in range(10):
        floger.debug('number is %d' % i)
        sloger.debug('number is %d' % i)
