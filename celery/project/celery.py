from __future__ import absolute_import
from celery import Celery

# http://docs.celeryproject.org/en/latest/getting-started/next-steps.html
app = Celery('project', broker='amqp://', backend='amqp://',
             include=['project.tasks'])

# Optional configuration, see the application user guide.
app.conf.update(
    CELERY_TASK_RESULT_EXPIRES=3600,
    CELERY_IGNORE_RESULT=False,  # Default: True
)

if __name__ == '__main__':
    app.start()


# Start worker
# celery ->> celery multi start worker001 -A project -l info
# celery multi v3.1.24 (Cipater)
# > Starting nodes...
# 	> worker001@seclab.local: OK
# celery ->> celery multi start worker002 -A project -l info
# celery multi v3.1.24 (Cipater)
# > Starting nodes...
# 	> worker002@seclab.local: OK

# Stop worker
# celery ->> celery multi stop worker002 -A project -l info
# celery multi v3.1.24 (Cipater)
# > Stopping nodes...
# 	> worker002@seclab.local: TERM -> 21118
# celery ->> celery multi stop worker001 -A project -l info
# celery multi v3.1.24 (Cipater)
# > Stopping nodes...
# 	> worker001@seclab.local: TERM -> 21074
