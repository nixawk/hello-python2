#!/usr/bin/python
# -*- coding: utf8 -*-

# =------------------------------------------------------------=
# ## Usage
# 1. Install databases
# $ sudo apt-get install redis-server mongodb-server

# 2. Install apscheduler framework
# $ sudo pip install apscheduler gevent pymongo

# 3. Custom a exploit function called exp as follow.

# ## References
# http://apscheduler.readthedocs.io/en/latest/userguide.html
# =------------------------------------------------------------=

from apscheduler.schedulers.gevent import GeventScheduler
from apscheduler.jobstores.mongodb import MongoDBJobStore
from apscheduler.executors.pool import ThreadPoolExecutor, ProcessPoolExecutor

from pymongo import MongoClient
from redis import Redis

from pytz import utc

import logging
import os


logging.basicConfig(level=logging.CRITICAL)


class Bulk(object):
    """Autopwn framwork"""

    def __init__(self):
        """Init redis/mongodb"""
        self.redis = Redis(host='localhost', port=6379, db=0)
        self.redis_key = 'hosts'

        self.mongo = MongoClient('mongodb://localhost:27017/')
        self.mongo_dbname = 'database'
        self.mongo_clname = 'collection'
        self.mongo_col = self.mongo[self.mongo_dbname][self.mongo_clname]

        self.poolsize = 800
        self.procsize = 8

    def add_job_target(self, iterator):
        """Put all targets into redis database"""
        self.redis.lpush(self.redis_key, *[_ for _ in iterator])

    def add_job_result(self, result):
        """Save all results into mongodb database"""
        self.mongo_col.insert(result)  # result is a json/dict object

    def job_worker(self):
        """Pop a target from redis, and handle it with custom function"""
        ret = ''
        data = self.redis.lpop(self.redis_key)

        if data:
            data = data.strip()
            try:
                ret = self.exploit(data)
            except Exception as err:
                ret = err

        record = {'record': data, 'result': ret}
        self.add_job_result(record)  # result is a json/dict object

    def run(self):
        """Start apscheduler tasks"""
        jobstores = {'mongo': MongoDBJobStore()}

        executors = {
            'default': ThreadPoolExecutor(self.poolsize),
            'processpool': ProcessPoolExecutor(self.procsize)
        }

        job_defaults = {'coalesce': False, 'max_instances': 3}

        scheduler = GeventScheduler()
        scheduler.configure(
            jobstores=jobstores,
            executors=executors,
            job_defaults=job_defaults,
            timezone=utc)
        scheduler.add_job(self.job_worker, 'interval', seconds=0.001)

        green_let = scheduler.start()
        print('Ctrl+{0} to exit.'.format('Break' if os.name == 'nt' else 'C'))

        # Execution will block here util Ctrl+C (Ctrl+Break on Windows).
        try:
            green_let.join()
        except (KeyboardInterrupt, SystemExit):
            pass

    def exploit(self, host):
        """Cutsom your exploit function"""
        status = ''   # save status into mongodb database
        if host:
            status = host
        return status


def custom_exploit(host):
    status = ''
    # code here
    return status


if __name__ == '__main__':
    # Notice: please install redis and mongodb at first.
    auto = Bulk()

    # Read hosts from a file
    # auto.add_job_target(open('/tmp/wordlists'))

    # Put hosts into redis
    # auto.redis.lpush('hosts', *[_ for _ in range(100)])

    # custom exploit function
    # auto.exploit = custom_exploit

    auto.run()
