#!/usr/bin/env python
# -*- coding: utf8 -*-

from ctypes import *


def MessageBox(hWnd, lpText, lpCaption, uType):
    """
    int WINAPI MessageBox(
          _In_opt_ HWND    hWnd,
          _In_opt_ LPCTSTR lpText,
          _In_opt_ LPCTSTR lpCaption,
          _In_     UINT    uType
    );
    """

    msg = windll.user32.MessageBoxA
    msg.argtypes = [c_int, c_char_p, c_char_p, c_int]
    ret = msg(hWnd, lpText, lpCaption, uType)

    return ret


if __name__ == "__main__":
    MessageBox(0, "Hello, World", "Tom says:", 0)
