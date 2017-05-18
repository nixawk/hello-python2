#!/usr/bin/python
# -*- coding: utf-8 -*-

from passlib.hash import sha256_crypt


def sha256_password(password):
    return sha256_crypt.encrypt(password)


def valid_sha256_password(password, sha256_hash):
    return sha256_crypt.verify(password, sha256_hash)


if __name__ == '__main__':
    password = "password"

    for i in range(10):
        crypt_password = sha256_password('password')
        valid_hash = valid_sha256_password(password, crypt_password)

        print("{} - {} - {}".format(i, crypt_password, valid_hash))


"""
0 - $5$rounds=535000$9gmELdOLSQYhgJAL$u1wCZDqBbF5sb1Mg0gz4GHaXKlLz8mjBvfworh07RkD - True
1 - $5$rounds=535000$DBfa6B9bB3Wg91X7$oxthSdpJqVE6k5LtCMVYrYiALSsFYbyxO9jQPV77Qc4 - True
2 - $5$rounds=535000$yG2OjGhC8qYXWI.h$Tl2edVicbSqYyWzvI32w3VFerzKxAyYBwEF0e4h6ND9 - True
3 - $5$rounds=535000$duAmWfJ8bK5lCIuF$CTXS0s6LxLxtedNir3XBi4CYO2htrc2VdoPCgmuuDdC - True
4 - $5$rounds=535000$ZNU74ci4PX2gvzKr$9tEmXogXQyXywyRv6Yg2yaL7JctHLOGQulxlsZCAe36 - True
5 - $5$rounds=535000$TlH.TpA3HaaRonUu$DNhKcY5vyAV1MnNumZX.m1ORZYGY/.iycVKFxJnDO/. - True
6 - $5$rounds=535000$vEiTdv4yKMh2zVkR$6H/LbvmSYcczG4ySrIKyF/xpB9FF0pWmx.OaHVR7oM7 - True
7 - $5$rounds=535000$ZaTVX3UBklNtzWmz$TuldeVjarI.RUXVA9CYKpAqlhIl04xNq4stJ2RGmTvA - True
8 - $5$rounds=535000$ZlKPdxpvoLyNwhGy$q3ILEITSpBpqze4x3x9kZZ9bcKmsw.y.yo2GGEU6DJ4 - True
9 - $5$rounds=535000$EGg5UfrJ697PPSqR$UQ8J3b2Ip2elFe/Vl0tOoHdQQ1nZ7x5Tl.ffZ/dRV0C - True
"""
