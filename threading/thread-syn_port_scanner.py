#!/usr/bin/env python
# -*- coding: utf8 -*-

import thread
import Queue
from scapy.all import *


def syn(host, port=80):
    """syn port scanner"""

    print "[*] %s" % host

    resp = sr1(IP(dst=host)/TCP(dport=port), verbose=False, timeout=0.4)

    if resp and resp.haslayer('TCP'):
        _tcp = resp.getlayer('TCP')

        if _tcp.flags == 0x12:
            print "[+] %s:%d is open" % (host, port)


def worker_thread(que):
    while True:
        if que.empty():
            print "[*] Game Over !"
            break

        syn(que.get())

if __name__ == "__main__":
    que = Queue.Queue()

    for h in range(1, 255):
        que.put("54.208.99.%d" % h)

    for i in range(6):
        thread.start_new_thread(worker_thread, (que,), {})

    while True:
        pass
