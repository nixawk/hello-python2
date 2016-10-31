#!/usr/bin/python
# -*- coding: utf8 -*-

# http://docs.celeryproject.org/en/latest/userguide/application.html
from celery import Celery


exploit = Celery('exploit', broker='redis://')


@exploit.task
def job(target):
    return "exploit {}".format(target)


if __name__ == "__main__":
    exploit.worker_main()  # the tasks module is used to start a worker.
