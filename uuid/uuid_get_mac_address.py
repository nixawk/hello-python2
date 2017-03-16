#!/usr/bin/python

from uuid import getnode


def get_mac():
    mac = hex(getnode())
    return [mac[i: i+2] for i in range(2, len(mac), 2)]


if __name__ == "__main__":
    mac = get_mac()
    print(":".join(mac))  # 66:55:44:33:22:11
    print("-".join(mac))  # 66-55-44-33-22-11
