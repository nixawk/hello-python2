from __future__ import absolute_import
import signal

# Ctrl + C to quit
# https://gist.github.com/lechup/d886e89490b2f6c737d7#comment-1253485
import gevent.monkey
gevent.monkey.patch_all()

import gevent
import gevent.pool

from rq import Worker
from rq.timeouts import BaseDeathPenalty, JobTimeoutException
from rq.worker import StopRequested, green, blue
from rq.exceptions import DequeueTimeout


class GeventDeathPenalty(BaseDeathPenalty):
    def setup_death_penalty(self):
        exception = JobTimeoutException('Gevent Job exceeded maximum timeout value (%d seconds).' % self._timeout)
        self.gevent_timeout = gevent.Timeout(self._timeout, exception)
        self.gevent_timeout.start()

    def cancel_death_penalty(self):
        self.gevent_timeout.cancel()


class GeventWorker(Worker):
    death_penalty_class = GeventDeathPenalty

    def __init__(self, *args, **kwargs):
        pool_size = kwargs.get('pool_size', 50)
        self.gevent_pool = gevent.pool.Pool(pool_size)
        super(GeventWorker, self).__init__(*args, **kwargs)

    def get_ident(self):
        return id(gevent.getcurrent())

    def handle_warm_shutdown_request(self):
        self.log.warning('Warm shut down requested.')
        self.log.warning('Stopping after all greenlets are finished. '
                         'Press Ctrl+C again for a cold shutdown.')

    def request_stop(self, signum, frame):
        """Stops the current worker loop but waits for child processes to
        end gracefully (warm shutdown).
        """
        self.log.debug('Got signal {0}'.format(signal_name(signum)))

        gevent.signal(signal.SIGINT, self.request_force_stop)
        gevent.signal(signal.SIGTERM, self.request_force_stop)

        self.handle_warm_shutdown_request()

        self._stop_requested = True
        # self._stopped = True
        self.gevent_pool.join()
        raise StopRequested()

    def _install_signal_handlers(self):
        """Installs signal handlers for handing SIGINT and SIGTERM
        gracefully.
        """
        gevent.signal(signal.SIGINT, self.request_stop)
        gevent.signal(signal.SIGTERM, self.request_stop)

    def request_force_stop(self, signum, frame):
        """Terminates the application (cold shutdown)
        """
        self.log.warning('Cold shut down.')
        self.gevent_pool.kill()
        raise SystemExit()

    def execute_job(self, job, queue):
        """Execute job in gevent mode"""
        self.gevent_pool.spawn(self.perform_job, job, queue)

    def dequeue_job_and_maintain_ttl(self, timeout):
        if self._stop_requested:
            raise StopRequested()

        result = None

        while True:
            self.heartbeat()
            # do jobs in pool before adding new one
            while not self.gevent_pool.free_count() > 0:
                gevent.sleep(0)

            try:
                result = self.queue_class.dequeue_any(self.queues, timeout, connection=self.connection)
                if result is None and timeout is None:
                    self.gevent_pool.join()
                if result is not None:
                    job, queue = result
                    self.log.info('%s: %s (%s)' % (green(queue.name),
                                  blue(job.description), job.id))
                break
            except DequeueTimeout:
                pass

        self.heartbeat()
        return result
