#!/usr/bin/python
# -*- coding: utf8 -*-

# http://docs.celeryproject.org/en/latest/userguide/application.html
# http://docs.celeryproject.org/en/latest/configuration.html#configuration

from celery import Celery


exploit = Celery('exploit', broker='redis://')
exploit.conf.CELERY_TIMEZONE = 'Europe/Landon'


exploit.conf.update(
    # BROKER_URL='amqp://guest:guest@localhost:5672//',
    # CELERY_IMPORTS=('project.tasks', ),
    # CELERY_TASK_RESULT_EXPIRES=3600,
    # CELERY_IGNORE_RESULT=False,  # Default: True

    # Time and date settings
    CELERY_ENABLE_UTC=True,
    CELERY_TIMEZONE='Europe/London',

    # Task settings
    # CELERY_ANNOTATIONS={'exploit.job': {'rate_limit': '10/s'}}
    # CELERY_ANNOTATIONS={'*': {'rate_limit': '10/s'}}

    # Concurrency settings
    # CELERYD_PREFETCH_MULTIPLIER

    # Task result backend settings
    # CELERY_RESULT_BACKEND='db+sqlite:///results.db',
    # CELERY_RESULT_SERIALIZER='json'

    # Database backend settings
    # CELERY_RESULT_BACKEND
    # CELERY_RESULT_DBURI
    # CELERY_RESULT_ENGINE_OPTIONS
    CELERY_RESULT_PERSISTENT=True,

    # Cache backend settings
    # CELERY_CACHE_BACKEND_OPTIONS
    # CELERY_CACHE_BACKEND

    # Redis backend settings
    # CELERY_REDIS_MAX_CONNECTIONS

    # MongoDB backend settings
    # CELERY_MONGODB_BACKEND_SETTINGS

    # See more details:
    # http://docs.celeryproject.org/en/latest/configuration.html#configuration
)

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# config_from_object
# loads configuration from a configuration object.

#     exploit.config_from_object('celeryconfig')

# The [celeryconfig.py] module may then look like this:
#     CELERY_ENABLE_UTC = True
#     CELERY_TIMEZONE = 'Europe/London'
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#
#  import celeryconfig
#  exploit.config_from_object(celeryconfig)
#
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#
#  class Config():
#      CELERY_ENABLE_UTC = True,
#      CELERY_TIMEZONE = 'Europe/London',
#
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++

exploit.conf.humanize(with_defaults=False, censored=True)
exploit.conf.table(with_defaults=False, censored=True)


@exploit.task
def job(target):
    return target
