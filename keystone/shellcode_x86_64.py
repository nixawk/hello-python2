#!/usr/bin/python
# -*- coding: utf-8 -*-

# Author: Nixawk

# sudo pip install keystone-engine

"""
$ cat /tmp/shellcode.asm
mov rax,0x1
add rax,0x2
$ python2.7 shellcode_x86_64.py /tmp/shellcode.asm
[*] shellcode_x86_64_byAsmFile - generate shellcode with asm in /tmp/shellcode.asm
[*] shellcode_x86_64_byAsmCode - remove comments in asmcode
[*] shellcode_x86_64_byAsmCode - generate shellcode
[*] shellcode_x86_64_byAsmCode - output c shellcode
\x48\xc7\xc0\x01\x00\x00\x00\x48\x83\xc0\x02
"""

from keystone import *

import logging
import sys


logging.basicConfig(level=logging.DEBUG, format="[*] %(funcName)s - %(message)s")
log = logging.getLogger(__name__)


def shellcode_x86_64_byAsmCode(asmcode):
    ks = Ks(KS_ARCH_X86, KS_MODE_64)  # x86_64 shellcodes

    log.debug("remove comments in asmcode")
    asmcode = [_ for _ in asmcode.splitlines() if _ and (not _.startswith(';'))]
    asmcode = ';'.join(asmcode)

    log.debug("generate shellcode")
    shellcode, length = ks.asm(asmcode)

    log.debug("output c shellcode")
    shellcode = ["\\x%02x" % _ for _ in shellcode]
    shellcode = "".join(shellcode)

    return shellcode

def shellcode_x86_64_byAsmFile(file):
    shellcode = ''

    with open(sys.argv[1]) as asmfile:
        log.info("generate shellcode with asm in %s", file)
        asmcode = asmfile.read()
        shellcode = shellcode_x86_64_byAsmCode(asmcode)

    return shellcode

if __name__ == '__main__':
    # asmcode = 'mov rax, 0x1;add rax, 0x2'

    if len(sys.argv) != 2:
        log.info("[*] python {} <shellcode.asm>")
        sys.exit(0)

    shellcode = shellcode_x86_64_byAsmFile(sys.argv[1])
    print(shellcode)