#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
In the event of a network problem (e.g. DNS failure, refused connection,
etc), Requests will raise a ConnectionError exception.

In the rare event of an invalid HTTP response,  Requests will raise an
HTTPError exception.

If a request times out, a Timeout exception is raised.

If a request exceeds the configured number of maximum rediections, a
TooManyRedirects exception is raised.

All exceptions that Requests explicitly raises inherit from
requests.exceptions.RequestException
"""
