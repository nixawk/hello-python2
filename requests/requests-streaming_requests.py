#!/usr/bin/python
# -*- coding: utf-8 -*-

import json
import requests


r = requests.get('http://httpbin.org/stream/20', stream=True)

for line in r.iter_lines():
    # filter out keep-alive new lines
    if line:
        print(json.loads(line))

"""
iter_lines() is not reentrant safe. Calling this method multiple
times  casuses some of the received data being lost. In case you need
to call it from multiple places, using the resulting iterator object
instead:

    lines = r.iter_lines()
    # Save the first line for later or just skip it
    first_line = next(lines)
    for line in lines:
        print(line)

"""
