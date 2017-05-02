#!/usr/bin/python
# -*- coding: utf-8 -*-

import ast


data = "{'key': 'value'}"
print(type(data))

data = ast.literal_eval(data)
print(type(data))