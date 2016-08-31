#!/usr/bin/python
# -*- coding: utf-8 -*-

# Please install python redis library as follow:

# $ sudo apt-get install python-redis
# or
# $ sudo pip install redis

import redis


# http://stackoverflow.com/questions/24392141/redis-python-db-0-parameter-used-for
# http://www.rediscookbook.org/multiple_databases.html
db = redis.Redis(host='localhost', port=6379, db=0)

db_key = 'hosts'
db_val = ['8.8.8.8', '8.8.4.4', 'www.google.com', 'redis.io']

db.lpush(db_key, *db_val)

while True:
    host = db.lpop(db_key)
    if not host: break
    print(host)
