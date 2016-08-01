#!/usr/bin/python
# -*- coding: utf-8 -*-


import logging
import threading
import Queue
import subprocess


logging.basicConfig(level=logging.INFO, format="%(message)s")


def ping(ip):
    command = 'ping -c 2 -t 3 {} 2>/dev/null | grep " bytes from " | cut -d ":" -f 1 | sort -u'.format(ip)
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    logging.info("{} - ({}), ({})".format(ip, repr(process.stdout.read()), repr(process.stderr.read())))


def worker_thread(que):
    while True:
        if que.empty():
            break

        ping(que.get())

if __name__ == "__main__":
    que = Queue.Queue()

    for h in range(1, 255):
        que.put("10.11.1.%d" % h)

    # Thread num: 20
    threads = [threading.Thread(target=worker_thread, args=(que,), kwargs={}) for i in range(20)]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
