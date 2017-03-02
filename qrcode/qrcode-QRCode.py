#!/usr.bin/python
# -*- coding: utf-8 -*-

import qrcode


def generate_QRCode(text):
    """Translate a text string into QRCode
    """
    qrc = qrcode.QRCode(version=1, box_size=10, border=1)
    qrc.add_data(text)
    qrc.make(fit=True)
    # qrc.print_ascii(invert=True)
    qrc.print_tty()


if __name__ == '__main__':
    text = "https://www.example.com"
    generate_QRCode(text)
