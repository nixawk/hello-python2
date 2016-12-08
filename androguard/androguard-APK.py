#!/usr/bin/python
# -*- coding: utf-8 -*-

from androguard.misc import APK
from pprint import pprint
import sys


def analysis(apkfile):
    app = APK(apkfile)

    if not app.is_valid_APK():
        print('{} is not a valid apk')
        sys.exit(0)

    pprint(app.filename)
    pprint(app.androidversion)
    pprint(app.files)

    # app._patch_magic
    # app.androidversion
    # app.arsc
    # app.axml
    # app.declared_permissions
    # app.filename
    # app.files
    # app.files_crc32
    # app.format_value
    # app.get_AndroidManifest
    # app.get_activities
    # app.get_android_manifest_axml
    # app.get_android_manifest_xml
    # app.get_android_resources
    # app.get_androidversion_code
    # app.get_androidversion_name
    # app.get_app_name
    # app.get_certificate
    # app.get_declared_permissions
    # app.get_declared_permissions_details
    # app.get_details_permissions
    # app.get_dex
    # app.get_element
    # app.get_elements
    # app.get_file
    # app.get_filename
    # app.get_files
    # app.get_files_crc32
    # app.get_files_information
    # app.get_files_types
    # app.get_intent_filters
    # app.get_libraries
    # app.get_main_activity
    # app.get_max_sdk_version
    # app.get_min_sdk_version
    # app.get_package
    # app.get_permissions
    # app.get_providers
    # app.get_raw
    # app.get_receivers
    # app.get_requested_aosp_permissions
    # app.get_requested_aosp_permissions_details
    # app.get_requested_permissions
    # app.get_requested_third_party_permissions
    # app.get_services
    # app.get_signature
    # app.get_signature_name
    # app.get_target_sdk_version
    # app.is_valid_APK
    # app.magic_file
    # app.new_zip
    # app.package
    # app.permission_module
    # app.permissions
    # app.show
    # app.valid_apk
    # app.xml
    # app.zip
    # app.zipmodule


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('{} <apkfile>'.format(sys.argv[0]))
        sys.exit(0)

    analysis(sys.argv[1])
