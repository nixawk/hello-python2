#!/usr/bin/env python
# -*- coding: utf8 -*-

import threading
import logging

logging.basicConfig(level=logging.DEBUG,
                    format='(%(threadName)-10s) %(message)s')


class ThreadDemo(threading.Thread):

    def __init__(self, group=None, target=None, name=None,
                 args=(), kwargs=None, verbose=None):
        threading.Thread.__init__(self, group=group, target=target,
                                  name=name, verbose=verbose)
        self.args = args
        self.kwargs = kwargs
        return

    def run(self):
        logging.debug('running with %s and %s' % (self.args, self.kwargs))
        return


for i in range(5):
    t = ThreadDemo(args=(i, i+1), kwargs={'a': 1, 'b': 2})
    t.start()
