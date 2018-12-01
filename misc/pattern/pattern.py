#!/usr/bin/python
# -*- coding: utf-8 -*-

# Author : Nixawk
# Python : python2/python3

LowerAlpha = 'abcdefghijklmnopqrstuvwxyz'
UpperAlpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
Numerals   = '0123456789'


def converge_sets(sets, idx, offsets, length):
    """https://github.com/rapid7/rex-text/blob/master/lib/rex/text.rb
    """
    buf = sets[idx][offsets[idx]]

    if ((idx + 1) < len(sets)) and (sets[idx + 1]):
        buf += converge_sets(sets, idx + 1, offsets, length)
    else:
        offsets[idx] = (offsets[idx] + 1) % len(sets[idx])
        while (idx >= 0 and offsets[idx] == 0):
            idx -= 1
            offsets[idx] = (offsets[idx] + 1) % len(sets[idx])

        if (idx < 0):
            return buf

    return buf


def pattern_create(length, sets=[]):
    """https://github.com/rapid7/metasploit-framework/blob/master/tools/exploit/pattern_create.rb
    """

    buf = ''
    offsets = []

    sets.extend([UpperAlpha, LowerAlpha, Numerals])

    if length < 1:
        return ''

    if len(sets) == 1 and len(sets[0]) == 1:
        return sets[0][0]

    for _ in range(len(sets)):
        offsets.append(0)

    while len(buf) < length:
        buf += converge_sets(sets, 0, offsets, length)

    return buf[0: length]


def pattern_offset(pattern, value, start=0):
    """https://github.com/rapid7/metasploit-framework/blob/master/tools/exploit/pattern_offset.rb
    """
    if isinstance(value, str):
        return pattern.index(value, start)
    elif isinstance(value, int):
        import binascii
        value2 = binascii.unhexlify(value)
        return pattern.index(value2, start)
    else:
        raise Exception("Invalid class for value: %s" % value.__class__)



if __name__ == '__main__':

    import sys

    if len(sys.argv) < 3:
        print("[*] Usage: python %s [option]" % sys.argv[0])
        print("    python pattern.py create 5000")
        print("    python pattern.py offset 5000 [Ae2A | 41653241]")
        sys.exit(0)

    if sys.argv[1].upper() == "CREATE":
        if sys.argv[2].isdigit():
            length = int(sys.argv[2])
            patbuf = pattern_create(length)
            print(patbuf)
        else:
            print("need a length arg")

    elif sys.argv[1].upper() == "OFFSET":
        if sys.argv[2].isdigit():
            length = int(sys.argv[2])
            offstr = sys.argv[3]
            patbuf = pattern_create(length)
            print("offset: %d" % pattern_offset(patbuf, offstr))
        else:
            print("need a length arg")

    else:
        print("Unknown pattern action")


## References

# https://github.com/rapid7/metasploit-framework/blob/master/tools/exploit/pattern_create.rb
# https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit.rb#L1220
# https://github.com/rapid7/rex-text/blob/master/lib/rex/text/pattern.rb
# https://github.com/rapid7/rex-text/blob/master/lib/rex/text.rb
