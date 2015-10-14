#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import aes

# mode:
#     aes.AESModeOfOperation.modeOfOperation = {'CBC': 2, 'CFB': 1, 'OFB': 0}
#     AESModeOfOperation.modeOfOperation["CBC"] = 2
#     AESModeOfOperation.modeOfOperation["CFB"] = 1
#     AESModeOfOperation.modeOfOperation["CBC"] = 0


def genAESKey(size):
    """generate a new AES key for encryption/decryption"""
    return aes.generateRandomKey(size)


def encryptAES(key, data, mode=2):
    """encrypt data with aes key"""
    return aes.encryptData(key, data, mode)


def decryptAES(key, data, mode=2):
    """decrypt data with aes key"""
    return aes.decryptData(key, data, mode)


if __name__ == "__main__":
    key = genAESKey(16)
    data = '/Hello AES/'
    en_data = encryptAES(key, data)
    de_data = decryptAES(key, en_data)

    print("KEY          :", key)
    print("DATA         :", data)
    print("ENCRYPT DATA :", en_data)
    print("DECRYPT DATA :", de_data)
