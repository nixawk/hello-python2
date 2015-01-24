#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import urlparse


print urlparse.parse_qs('name=aaaa&id=123')
print urlparse.parse_qsl('name=aaaa&id=123')
