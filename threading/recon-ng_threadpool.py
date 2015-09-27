#!/usr/bin/env python
# -*- coding: utf-8 -*-

# From /opt/recon-ng/recon/mixins/threads.py

from Queue import Queue, Empty
import threading
import time
import logging


logging.basicConfig(level=logging.INFO, format="[+] %(message)s")
logger = logging.getLogger("mutilthreads")


class ThreadingMixin(object):
    def __init__(self):
        self.stopped = threading.Event()
        self.queue = Queue()
        self.threadNum = 10

    def _thread_wrapper(self, *args):
        while not self.stopped.is_set():
            try:
                item = self.queue.get_nowait()
            except Empty:
                continue

            try:
                self.module_thread(item, *args)
            except:
                logger.info('thread exception')
            finally:
                self.queue.task_done()

    def threads(self, *args):
        [self.queue.put(_) for _ in args[0]]

        threads = [
            threading.Thread(target=self._thread_wrapper, args=args[1:])
            for i in range(self.threadNum)
        ]

        [_.setDaemon(True) for _ in threads]
        [_.start() for _ in threads]

        try:
            while not self.queue.empty():
                time.sleep(0.7)
        except KeyboardInterrupt:
            self.stopped.set()
            [_.join() for _ in threads]

        self.queue.join()
        self.stopped.set()

    def module_thread(self, item, *args):
        logger.info(item)
        pass


if __name__ == '__main__':
    # define a new ThreadingMixin's subclass
    class demo(ThreadingMixin):
        def __init__(self):
            super(demo, self).__init__()

        def module_thread(self, item, callback):
            logger.info(callback(item))

    def callback(word):
        return "abc - %s" % word

    words = []
    with open('wordlists.txt') as f:
        words = [i.strip() for i in f]

    d = demo()
    d.threads(words, callback)
