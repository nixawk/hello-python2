#!/usr/bin/python
# -*- coding: utf-8 -*-

from androguard.misc import APK
import sys

"""
[*] ------ [/tmp/demo.apk] permissions: ------

<uses-permission android:name="android.permission.INTERNET">
<uses-permission android:name="android.permission.CALL_PHONE">
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE">
<uses-permission android:name="android.permission.READ_PHONE_STATE">
<uses-permission android:name="android.permission.MODIFY_AUDIO_SETTINGS">
<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW">
<uses-permission android:name="android.permission.ACCESS_WIFI_STATE">
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE">
<uses-permission android:name="android.permission.VIBRATE">
<uses-permission android:name="android.permission.CAMERA">
<uses-permission android:name="android.permission.GET_TASKS">
<uses-permission android:name="android.permission.WRITE_SETTINGS">
<uses-permission android:name="android.permission.CHANGE_WIFI_STATE">
<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED">
<uses-permission android:name="android.permission.ACCESS_DOWNLOAD_MANAGER">
<uses-permission android:name="android.permission.DOWNLOAD_WITHOUT_NOTIFICATION">
<uses-permission android:name="android.permission.DISABLE_KEYGUARD">
<uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION">
<uses-permission android:name="android.permission.EXPAND_STATUS_BAR">
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION">
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION">
<uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION">
"""


def dump_permissions(apkfile):
    return [perm
            for perm in APK(apkfile).get_AndroidManifest().toxml().splitlines()
            if 'android.permission' in perm.lower()]

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: {} <apkfile>".format(sys.argv[0]))
        sys.exit(0)

    apkfile = sys.argv[1]
    print('\n[*] ------ [{}] permissions: ------\n'.format(apkfile))
    for _ in dump_permissions(apkfile):
        print(_)
