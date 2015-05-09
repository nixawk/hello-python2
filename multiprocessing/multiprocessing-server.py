#!/usr/bin/env python
# -*- coding: utf8 -*-

from multiprocessing.connection import Listener


serv = Listener(address=("127.0.0.1", 8080), authkey="password")
c = serv.accept()
c.send("haha !\n")
