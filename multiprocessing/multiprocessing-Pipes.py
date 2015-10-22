#!/usr/bin/python
# -*- coding: utf-8 -*-

from multiprocessing import Process, Pipe


def f(conn):
    conn.send([42, None, 'hello'])
    conn.close()


if __name__ == '__main__':
    parent_conn, child_conn = Pipe()
    p1 = Process(target=f, args=(child_conn,))
    p2 = Process(target=f, args=(parent_conn,))
    p1.start()
    p2.start()
    print parent_conn.recv()
    print child_conn.recv()
    p1.join()
    p2.join()
