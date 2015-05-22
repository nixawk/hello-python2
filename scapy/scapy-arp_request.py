#!/usr/bin/env python
# -*- coding: utf8 -*-

from scapy.all import *
import logging

import threading
import Queue


logging.basicConfig(level=logging.DEBUG,
                    format='[*] %(name)s - %(message)s')
logger = logging.getLogger('arpscanner')

# disable scapy verbose mode
conf.verb = 0

# disable scapy warning
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def arpscanner(iplist, lock):
    """Scan internal mac addresses"""
    while 1:
        try:
            lock.acquire()
            ip = iplist.get_nowait()
            lock.release()

            # create a ether object
            ether = Ether(type=0x0806)

            # create a arp object
            arp = ARP(op=1, hwdst='ff:ff:ff:ff:ff:ff', pdst=ip)

            # send arp request and receive response
            arpres = srp1(ether/arp, timeout=0.05)

            if arpres and arpres.haslayer('ARP'):
                logger.info('%s \t %s' % (ip, arpres['ARP'].hwsrc))
            else:
                logger.debug('%s \t %s' % (ip, None))

        except Queue.Empty:
            lock.release()
            break

    return

if __name__ == "__main__":
    iplist = Queue.Queue()
    lock = threading.Lock()

    for i in range(1, 255, 1):
        ip = "192.168.1.%s" % i
        iplist.put(ip)

    for n in range(30):
        t = threading.Thread(target=arpscanner, args=(iplist, lock))
        t.start()
