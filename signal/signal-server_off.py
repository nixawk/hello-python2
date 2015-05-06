#!/usr/bin/env python
# -*- coding: utf8 -*-

import time
import signal
import threading
import sys
from optparse import OptionParser

if sys.version_info > (3, 0):
    from socketserver import TCPServer, BaseRequestHandler
else:
    from SocketServer import TCPServer, BaseRequestHandler


class server(object):
    def __init__(self, offtime):
        self.offtime = offtime

        self.server = TCPServer(
            ('127.0.0.1', 7654),
            BaseRequestHandler
        )
        self.server_thread = None
        self.server.running = False

    def shutdown(self, signum, frame):
        print("[*] Shutting down server thread")
        self.server.running = False
        self.server.shutdown()

    def up(self):
        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGALRM, self.shutdown)

        signal.alarm(self.offtime)

        self.server_thread = threading.Thread(target=self.server.serve_forever)
        print("[*] Starting server thread")

        self.server_thread.start()
        self.server.running = True
        print("[*] Waiting for server thread to shut down")

        while self.server.running:
            time.sleep(1)

        self.server_thread.join()
        print("[*] Server thread terminated")


def usage():
    usage = "[*] %prog -s 100 \n\tshutdown after 100 seconds"
    parser = OptionParser(usage=usage)
    parser.add_option('-s', dest='shutdown', type='int', help='shutdown time')
    (args, _) = parser.parse_args()

    if args.shutdown and isinstance(args.shutdown, int):
        print "[*] Shutdown server after << %d >> seconds" % args.shutdown
        server(args.shutdown).up()


if __name__ == '__main__':
    usage()
