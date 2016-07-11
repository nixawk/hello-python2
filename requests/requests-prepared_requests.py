#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Whenever you receive a Response object from an API call or Session
call, the request attribute is actually the PreparedRequest that was
used. In some cases you may wish to do some extra work to the body
or headers (or anything else really) before sending a request. The
simple recipe for this is the following:

"""

from request import Request, Session


def demo1(url, data, headers, stream, verify, proxies, cert, timeout):
    s = Session()
    req = Request('GET', url, data=data, headers=headers)
    prepped = req.prepare()   # -- prepare

    resp = s.send(prepped,
                  stream=stream,
                  verify=verify,
                  proxies=proxies,
                  cert=cert,
                  timeout=timeout)

    print(resp.status_code)

"""
Since you are not doing anything special with the Request object,
you prepare it immediately and modify the PreparedRequest object.
You then send that with the other parameters you would have sent
to requests.* and Session.*
"""

"""
However, the above code will lose some of the advantages of having
a Requests Session object. In particular, Session-level state such as
cookies will not get applied to your request. To get a
PreparedRequest with that state applied, replace the call to
Request.prepare() with a call to SEssion.prepare_request(), like this:
"""


def demo2(url, data, headers, stream, verify, proxies, cert, timeout):
    s = Session()
    req = Request('GET', url, data=data, headers=headers)
    prepped = s.prepare_request(req)   # -- prepare_request

    resp = s.send(prepped,
                  stream=stream,
                  verify=verify,
                  proxies=proxies,
                  cert=cert,
                  timeout=timeout)

    print(resp.status_code)
