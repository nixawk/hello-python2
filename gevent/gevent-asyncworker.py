#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
AsyncWorker
~~~~~~~~~~~

This module allows you to use custom functions with Gevent to make
asynchronous tasks easily.
"""

import traceback

try:
    import gevent
    from gevent import monkey as curious_george
    from gevent.pool import Pool
except ImportError:
    raise RuntimeError('Gevent is required.')


curious_george.patch_all(thread=False, select=False)


__all__ = (
    'Worker',
    'new_worker', 'run_worker',
    'map_workers', 'imap_workers'
)


class Worker(object):
    """Asynchronous worker.

    :param func: Custorm function which will do special task
    :param callback: Callback called on results.
                     Same as passing ``hook={'response': callback}``
    """
    def __init__(self, func, *args, **kwargs):
        self.func = func
        self.args = args
        self.kwargs = kwargs

        callback = self.kwargs.pop('callback', None)
        if callback:
            self.kwargs['hooks'] = {'response': callback}
        self.response = None

    def start(self, **kwargs):
        """Prepares worker based on parameter passed on constructor and
        optional ``kwargs``

        :returns ``Response``
        """
        merged_kwargs = {}
        merged_kwargs.update(self.kwargs)
        merged_kwargs.update(kwargs)

        try:
            self.response = self.func(*self.args, **merged_kwargs)
        except Exception as e:
            self.exception = e
            self.traceback = traceback.format_exc()

        return self


def new_worker(func, *args, **kwargs):
    """Create a new job worker

    :param func: special function
    :param args: function args
    :param kwargs: function kwargs
    """
    return Worker(func, *args, **kwargs)


def run_worker(worker, pool=None):
    """run the worker object using the specified pool. If a pool isn't
    specified this method blocks. Pools are useful because you can specify size
    and can hence limit concurrency.
    """
    if pool is not None:
        return pool.spawn(worker.start)

    return gevent.spawn(worker.start)


def map_workers(workers, size=None, exception_handler=None, gtimeout=None):
    """Concurrently converts a list of Requests to Responses.

    :param workers: a collection of worker objects.
    :param size: Specifies the number of workers to make at a time. If None, no throttling occurs.
    :param exception_handler: Callback function, called when exception occured. Params: Worker, Exception
    :param gtimeout: Gevent joinall timeout in seconds. (Note: unrelated to workers timeout)
    """
    workers = list(workers)

    pool = Pool(size) if size else None
    jobs = [run_worker(req, pool) for req in workers]
    gevent.joinall(jobs, timeout=gtimeout)

    ret = []

    for worker in workers:
        if worker.response is not None:
            ret.append(worker.response)
        elif exception_handler and hasattr(worker, 'exception'):
            ret.append(exception_handler(worker, worker.exception))
        else:
            ret.append(None)

    return ret


def imap_workers(workers, size=2, exception_handler=None):
    """Concurrently converts a generator object of Workers to
    a generator of Responses.
    :param workers: a generator of worker objects.
    :param size: Specifies the number of workers to make at a time. default is 2
    :param exception_handler: Callback function, called when exception occured. Params: Worker, Exception
    """
    pool = Pool(size)

    def start(r):
        return r.start()

    for worker in pool.imap_unordered(start, workers):
        if worker.response is not None:
            yield worker.response
        elif exception_handler:
            exception_handler(worker, worker.exception)

    pool.join()


if __name__ == "__main__":
    import requests
    urls = [
        'http://www.heroku.com',
        'http://python-tablib.org',
        'http://httpbin.org',
        'http://python-requests.org',
        'http://fakedomain/',
        'http://kennethreitz.com'
    ]

    reqs = [new_worker(requests.get, url) for url in urls]
    print map_workers(reqs, gtimeout=6.0)
