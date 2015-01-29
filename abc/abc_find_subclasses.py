#!/usr/bin/env python
# -*- coding: utf-8 -*-

from abc_base import PluginBase
import abc_subclass
import abc_register


for sc in PluginBase.__subclasses__():
    print sc.__name__
