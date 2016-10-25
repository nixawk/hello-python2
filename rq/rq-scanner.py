#!/usr/bin/python
# -*- coding: utf8 -*-

# http://python-rq.org/docs/
# sudo pip install rq
# sudo apt-get install redis-server
# rq worker
# rq info

from optparse import OptionParser
from optparse import OptionError
from redis import Redis
from rq import Queue
from exploit import job
import pickle


def usage():
    try:
        usage = "python %prog [options]"
        parser = OptionParser(usage=usage)
        parser.add_option('--hosts', dest='filename',
                          type='str',
                          help='a file include hosts')
        parser.add_option('--showresults', action='store_true',
                          help='show all scan results')
        (args, _) = parser.parse_args()

    except (OptionError, TypeError) as e:
        parser.error(e)
    else:
        return args


def push_hosts(filename):
    q = Queue(connection=Redis())
    for _ in open(filename):
        q.enqueue(job, _.strip(), result_ttl=86400)


def show_results():
    for job in Redis().keys():
        if not job.startswith('rq:job:'):
            continue

        json = Redis().hgetall(job)
        if not ('result' in json):
            continue

        print pickle.loads(json['result'])


if __name__ == '__main__':
    options = usage()
    if not (options.filename or options.showresults):
        print('-h for details')
    else:
        if options.filename: push_hosts(options.filename)
        if options.showresults: show_results()
