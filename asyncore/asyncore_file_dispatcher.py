#!/usr/bin/env python
# -*- coding: utf8 -*-

import asyncore
import os


class FileReader(asyncore.file_dispatcher):
    def writable(self):
        return False

    def handle_read(self):
        data = self.recv(256)
        print 'READ: (%d) "%s"' % (len(data), data)

    def handle_expt(self):
        # Ignore events that look like out of band data
        pass

    def handle_close(self):
        self.close()

fd = os.open('/tmp/1.txt', os.O_RDONLY)
reader = FileReader(fd)
asyncore.loop()
